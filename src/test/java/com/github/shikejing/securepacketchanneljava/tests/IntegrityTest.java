package com.github.shikejing.securepacketchanneljava.tests;

import com.github.shikejing.securepacketchanneljava.channel.ChannelConfig;
import com.github.shikejing.securepacketchanneljava.channel.CryptoUtil;
import com.github.shikejing.securepacketchanneljava.channel.LoopbackTransport;
import com.github.shikejing.securepacketchanneljava.channel.Message;
import com.github.shikejing.securepacketchanneljava.channel.PacketCodec;
import com.github.shikejing.securepacketchanneljava.channel.RejectReason;
import com.github.shikejing.securepacketchanneljava.channel.SecureSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/** 任何被改动的报文都必须在校验阶段被识别并拒绝，篡改内容不得交给上层。 */
class IntegrityTest {

    private LoopbackTransport[] link;
    private InterceptingTransport clientWire;
    private SecureSession client;
    private SecureSession server;

    @BeforeEach
    void setUp() throws Exception {
        link = LoopbackTransport.pair();
        clientWire = new InterceptingTransport(link[0]);
        client = SecureSession.client(1L, clientWire, ChannelConfig.defaults(), CryptoUtil.deterministicRandom(1L));
        server = SecureSession.server(1L, link[1], ChannelConfig.defaults(), CryptoUtil.deterministicRandom(2L));
        client.startHandshake();
        server.accept();
        client.completeHandshake();
        clientWire.clearSent();
    }

    private byte[] capturePacket(String payload) {
        clientWire.stopForwarding();
        client.send(payload.getBytes(StandardCharsets.UTF_8));
        clientWire.resumeForwarding();
        byte[] raw = clientWire.lastSent();
        clientWire.clearSent();
        return raw;
    }

    @Test
    void unmodifiedPacketIsAccepted() {
        byte[] raw = capturePacket("authentic");
        clientWire.injectRaw(raw);
        Optional<Message> got = server.pollMessage();
        assertTrue(got.isPresent());
        assertEquals("authentic", new String(got.get().payload(), StandardCharsets.UTF_8));
        assertEquals(1, server.stats().accepted());
        assertEquals(0, server.stats().totalRejected());
    }

    @Test
    void flippedCiphertextByteIsRejected() {
        byte[] raw = capturePacket("tampered-payload");
        // 翻转负载区域（报文尾部标签之前）的一个字节。
        raw[raw.length - CryptoUtil.TAG_LEN - 3] ^= 0x01;
        clientWire.injectRaw(raw);
        assertTrue(server.pollMessage().isEmpty(), "tampered content must not reach upper layer");
        assertEquals(1, server.stats().rejected(RejectReason.INTEGRITY_FAILURE));
        assertEquals(0, server.stats().accepted());
    }

    @Test
    void flippedTagByteIsRejected() {
        byte[] raw = capturePacket("tag-target");
        raw[raw.length - 1] ^= 0x40;
        clientWire.injectRaw(raw);
        assertTrue(server.pollMessage().isEmpty());
        assertEquals(1, server.stats().rejected(RejectReason.INTEGRITY_FAILURE));
    }

    @Test
    void flippedSequenceByteIsRejected() {
        byte[] raw = capturePacket("seq-target");
        // 序号位于头部：magic(2)+version(1)+type(1)+epoch(4) 之后的 8 字节。
        raw[8 + 7] ^= 0x01;
        clientWire.injectRaw(raw);
        assertTrue(server.pollMessage().isEmpty());
        // 序号被改大后落在窗口内或触发完整性失败，无论如何不得交付。
        assertEquals(0, server.stats().accepted());
    }

    @Test
    void truncatedPacketIsRejectedAsMalformed() {
        byte[] raw = capturePacket("truncate-me-please");
        byte[] truncated = Arrays.copyOf(raw, raw.length / 2);
        clientWire.injectRaw(truncated);
        assertTrue(server.pollMessage().isEmpty());
        assertEquals(1, server.stats().rejected(RejectReason.MALFORMED));
    }

    @Test
    void garbageBytesAreRejectedAsMalformed() {
        clientWire.injectRaw(new byte[]{0, 1, 2, 3, 4, 5, 6, 7});
        assertTrue(server.pollMessage().isEmpty());
        assertEquals(1, server.stats().rejected(RejectReason.MALFORMED));
    }

    @Test
    void sessionContinuesAfterTamperedPackets() {
        byte[] bad = capturePacket("bad");
        bad[bad.length - 2] ^= 0x10;
        clientWire.injectRaw(bad);
        assertTrue(server.pollMessage().isEmpty());

        // 会话不被毒化：后续正常报文仍然可用。
        client.send("after-attack".getBytes(StandardCharsets.UTF_8));
        Optional<Message> got = server.pollMessage();
        assertTrue(got.isPresent());
        assertEquals("after-attack", new String(got.get().payload(), StandardCharsets.UTF_8));
        assertEquals(1, server.stats().accepted());
        assertEquals(1, server.stats().rejected(RejectReason.INTEGRITY_FAILURE));
    }

    @Test
    void packetFromOtherSessionIsRejected() throws Exception {
        // 另一个会话（不同会话标识、不同密钥）的报文串到本会话链路上，必须完整性失败。
        LoopbackTransport[] foreignLink = LoopbackTransport.pair();
        InterceptingTransport foreignTap = new InterceptingTransport(foreignLink[0]);
        SecureSession foreignClient = SecureSession.client(55L, foreignTap, ChannelConfig.defaults(), CryptoUtil.deterministicRandom(21L));
        SecureSession foreignServer = SecureSession.server(55L, foreignLink[1], ChannelConfig.defaults(), CryptoUtil.deterministicRandom(22L));
        foreignClient.startHandshake();
        foreignServer.accept();
        foreignClient.completeHandshake();

        foreignTap.stopForwarding();
        foreignClient.send("foreign".getBytes(StandardCharsets.UTF_8));
        byte[] raw = foreignTap.lastSent();

        clientWire.injectRaw(raw);
        assertTrue(server.pollMessage().isEmpty());
        assertEquals(1, server.stats().rejected(RejectReason.INTEGRITY_FAILURE));
    }
}
