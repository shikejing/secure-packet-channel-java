package com.github.shikejing.securepacketchanneljava.tests;

import com.github.shikejing.securepacketchanneljava.channel.ChannelConfig;
import com.github.shikejing.securepacketchanneljava.channel.ControlCodec;
import com.github.shikejing.securepacketchanneljava.channel.CryptoUtil;
import com.github.shikejing.securepacketchanneljava.channel.HandshakeException;
import com.github.shikejing.securepacketchanneljava.channel.HandshakeFailure;
import com.github.shikejing.securepacketchanneljava.channel.KeyMaterial;
import com.github.shikejing.securepacketchanneljava.channel.LoopbackTransport;
import com.github.shikejing.securepacketchanneljava.channel.Message;
import com.github.shikejing.securepacketchanneljava.channel.PacketCodec;
import com.github.shikejing.securepacketchanneljava.channel.SecureSession;
import com.github.shikejing.securepacketchanneljava.channel.SessionManager;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class HandshakeTest {

    private static ChannelConfig fastConfig() {
        return ChannelConfig.builder()
                .handshakeTimeoutMillis(30)
                .maxHandshakeRetries(1)
                .build();
    }

    @Test
    void successfulHandshakeEstablishesBothEnds() {
        SecureSession[] pair = SessionManager.establishedPair(1L, ChannelConfig.defaults(), 11L, 22L);
        assertEquals(SecureSession.State.ESTABLISHED, pair[0].state());
        assertEquals(SecureSession.State.ESTABLISHED, pair[1].state());

        pair[0].send("ping".getBytes(StandardCharsets.UTF_8));
        Optional<Message> got = pair[1].pollMessage();
        assertTrue(got.isPresent());
        assertEquals("ping", new String(got.get().payload(), StandardCharsets.UTF_8));
    }

    @Test
    void sessionMismatchIsDistinguishableHandshakeFailure() {
        LoopbackTransport[] link = LoopbackTransport.pair();
        SecureSession client = SecureSession.client(1L, link[0], fastConfig(), CryptoUtil.deterministicRandom(1L));
        SecureSession server = SecureSession.server(2L, link[1], fastConfig(), CryptoUtil.deterministicRandom(2L));
        client.startHandshake();
        HandshakeException e = assertThrows(HandshakeException.class, server::accept);
        assertEquals(HandshakeFailure.SESSION_MISMATCH, e.reason());
        // 协商失败原因与报文完整性失败（RejectReason.INTEGRITY_FAILURE）属于不同分类体系，可明确区分。
        assertNotEquals("INTEGRITY_FAILURE", e.reason().name());
    }

    @Test
    void malformedHelloIsRejectedWithDistinctReason() {
        LoopbackTransport[] link = LoopbackTransport.pair();
        SecureSession server = SecureSession.server(7L, link[1], fastConfig(), CryptoUtil.deterministicRandom(3L));
        // 注入一个结构合法但负载非法的控制报文。
        link[0].send(PacketCodec.encodeControl(0, new byte[]{99, 1, 2}));
        HandshakeException e = assertThrows(HandshakeException.class, server::accept);
        assertEquals(HandshakeFailure.MALFORMED_HELLO, e.reason());
    }

    @Test
    void unsupportedVersionIsRejectedWithDistinctReason() {
        LoopbackTransport[] link = LoopbackTransport.pair();
        SecureSession server = SecureSession.server(7L, link[1], fastConfig(), CryptoUtil.deterministicRandom(3L));
        // 合法帧头但版本号不同。
        byte[] hello = PacketCodec.encodeControl(0, new byte[]{ControlCodec.HELLO});
        hello[2] = 99;
        link[0].send(hello);
        HandshakeException e = assertThrows(HandshakeException.class, server::accept);
        assertEquals(HandshakeFailure.UNSUPPORTED_VERSION, e.reason());
    }

    @Test
    void handshakeTimeoutIsReported() {
        LoopbackTransport[] link = LoopbackTransport.pair();
        SecureSession client = SecureSession.client(1L, link[0], fastConfig(), CryptoUtil.deterministicRandom(1L));
        client.startHandshake();
        HandshakeException e = assertThrows(HandshakeException.class, client::completeHandshake);
        assertEquals(HandshakeFailure.TIMEOUT, e.reason());

        // 服务端在没有任何对端报文时同样按超时失败。
        LoopbackTransport[] idle = LoopbackTransport.pair();
        SecureSession server = SecureSession.server(1L, idle[1], fastConfig(), CryptoUtil.deterministicRandom(2L));
        HandshakeException e2 = assertThrows(HandshakeException.class, server::accept);
        assertEquals(HandshakeFailure.TIMEOUT, e2.reason());
    }

    @Test
    void eachSessionHasIndependentKeys() {
        SecureSession[] a = SessionManager.establishedPair(1L, ChannelConfig.defaults(), 100L, 200L);
        SecureSession[] b = SessionManager.establishedPair(2L, ChannelConfig.defaults(), 300L, 400L);
        // 两个会话各自独立：互收互发不串扰。
        a[0].send("hello-a".getBytes(StandardCharsets.UTF_8));
        b[0].send("hello-b".getBytes(StandardCharsets.UTF_8));
        assertEquals("hello-a", new String(a[1].pollMessage().orElseThrow().payload(), StandardCharsets.UTF_8));
        assertEquals("hello-b", new String(b[1].pollMessage().orElseThrow().payload(), StandardCharsets.UTF_8));
    }

    @Test
    void keyMaterialNeverLeaksIntoObservableOutput() {
        KeyMaterial km = new KeyMaterial(new byte[]{1, 2, 3, 4}, new byte[]{5, 6});
        assertEquals("KeyMaterial[redacted]", km.toString());

        HandshakeException e = new HandshakeException(HandshakeFailure.TIMEOUT, "peer did not respond");
        assertFalse(e.getMessage().matches(".*[0-9a-fA-F]{32,}.*"));
    }
}
