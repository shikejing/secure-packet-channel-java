package com.github.shikejing.securepacketchanneljava.tests;

import com.github.shikejing.securepacketchanneljava.channel.ChannelConfig;
import com.github.shikejing.securepacketchanneljava.channel.ControlCodec;
import com.github.shikejing.securepacketchanneljava.channel.CryptoUtil;
import com.github.shikejing.securepacketchanneljava.channel.LoopbackTransport;
import com.github.shikejing.securepacketchanneljava.channel.Message;
import com.github.shikejing.securepacketchanneljava.channel.PacketCodec;
import com.github.shikejing.securepacketchanneljava.channel.RejectReason;
import com.github.shikejing.securepacketchanneljava.channel.SecureSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/** 断线重连：旧会话报文一律拒绝，恢复不重复处理，序号不回退不跳变。 */
class ReconnectTest {

    private InterceptingTransport clientWire;
    private SecureSession client;
    private SecureSession server;

    @BeforeEach
    void setUp() throws Exception {
        LoopbackTransport[] link = LoopbackTransport.pair();
        clientWire = new InterceptingTransport(link[0]);
        client = SecureSession.client(1L, clientWire, ChannelConfig.defaults(), CryptoUtil.deterministicRandom(1L));
        server = SecureSession.server(1L, link[1], ChannelConfig.defaults(), CryptoUtil.deterministicRandom(2L));
        client.startHandshake();
        server.accept();
        client.completeHandshake();
        clientWire.clearSent();
    }

    private static String payload(Message m) {
        return new String(m.payload(), StandardCharsets.UTF_8);
    }

    /** 客户端换新链路发起 RESUME，服务端在新链路上处理。 */
    private InterceptingTransport reconnect() throws Exception {
        LoopbackTransport[] link2 = LoopbackTransport.pair();
        InterceptingTransport wire2 = new InterceptingTransport(link2[0]);
        client.startReconnect(wire2);
        server.attachTransport(link2[1]);
        server.pollMessage(); // 处理 RESUME，回复 RESUME_ACK
        client.completeHandshake();
        return wire2;
    }

    @Test
    void reconnectRestoresSessionAndSequenceContinues() throws Exception {
        long s0 = client.send("m0".getBytes(StandardCharsets.UTF_8));
        long s1 = client.send("m1".getBytes(StandardCharsets.UTF_8));
        assertEquals("m0", payload(server.pollMessage().orElseThrow()));
        assertEquals("m1", payload(server.pollMessage().orElseThrow()));

        reconnect();
        assertEquals(1, client.generation());
        assertEquals(1, server.generation());
        assertEquals(SecureSession.State.ESTABLISHED, client.state());
        assertEquals(SecureSession.State.ESTABLISHED, server.state());

        // 序号只前进：不回退、不跳变。
        long s2 = client.send("m2".getBytes(StandardCharsets.UTF_8));
        assertEquals(s1 + 1, s2);
        assertEquals("m2", payload(server.pollMessage().orElseThrow()));
        assertEquals(3, server.stats().accepted());
        assertEquals(0, server.stats().totalRejected());
    }

    @Test
    void oldGenerationPacketsAreRejectedAfterReconnect() throws Exception {
        client.send("old-gen".getBytes(StandardCharsets.UTF_8));
        assertEquals("old-gen", payload(server.pollMessage().orElseThrow()));

        // 截留一条旧会话代的报文。
        clientWire.stopForwarding();
        client.send("old-copy".getBytes(StandardCharsets.UTF_8));
        byte[] oldPacket = clientWire.lastSent();
        clientWire.resumeForwarding();

        InterceptingTransport wire2 = reconnect();

        // 旧会话代的报文不得被新会话接受。
        wire2.injectRaw(oldPacket);
        assertTrue(server.pollMessage().isEmpty());
        assertEquals(1, server.stats().rejected(RejectReason.INTEGRITY_FAILURE));
        assertEquals(1, server.stats().accepted(), "旧报文不得被处理第二次");

        // 新会话继续正常工作。
        client.send("new-gen".getBytes(StandardCharsets.UTF_8));
        assertEquals("new-gen", payload(server.pollMessage().orElseThrow()));
    }

    @Test
    void replayedResumeFromOldGenerationIsRejected() throws Exception {
        client.send("x".getBytes(StandardCharsets.UTF_8));
        server.pollMessage();

        // 抓取本次 RESUME 的原始字节。
        LoopbackTransport[] link2 = LoopbackTransport.pair();
        InterceptingTransport wire2 = new InterceptingTransport(link2[0]);
        wire2.stopForwarding();
        client.startReconnect(wire2);
        byte[] resumeBytes = wire2.lastSent();
        wire2.resumeForwarding();
        wire2.injectRaw(resumeBytes); // 正常完成本次恢复
        server.attachTransport(link2[1]);
        server.pollMessage();
        client.completeHandshake();
        assertEquals(1, server.generation());

        // 把同一份 RESUME 再发一遍：旧会话代的恢复请求必须被拒绝。
        wire2.injectRaw(resumeBytes);
        assertTrue(server.pollMessage().isEmpty());
        assertEquals(1, server.stats().rejected(RejectReason.STALE_GENERATION));
        assertEquals(1, server.generation(), "会话代不得被旧 RESUME 改变");
    }

    @Test
    void resumeWithRolledBackSequenceIsRejected() throws Exception {
        client.send("a".getBytes(StandardCharsets.UTF_8));
        client.send("b".getBytes(StandardCharsets.UTF_8));
        server.pollMessage();
        server.pollMessage();

        // 伪造一个序号回退的 RESUME：lastSent=0 小于服务端已接收的序号。
        LoopbackTransport[] link2 = LoopbackTransport.pair();
        KeyPair ephemeral = CryptoUtil.generateX25519(CryptoUtil.deterministicRandom(99L));
        byte[] forged = ControlCodec.encodeHello(ControlCodec.RESUME, 1L, 1, 0, 0,
                CryptoUtil.encodePublic(ephemeral.getPublic()));
        server.attachTransport(link2[1]);
        link2[0].send(PacketCodec.encodeControl(0, forged));
        assertTrue(server.pollMessage().isEmpty());
        assertEquals(1, server.stats().rejected(RejectReason.STALE_GENERATION));
        assertEquals(0, server.generation(), "非法恢复不得改变会话状态");

        // 合法重连仍然可用：会话没有被破坏。
        reconnect();
        client.send("c".getBytes(StandardCharsets.UTF_8));
        assertEquals("c", payload(server.pollMessage().orElseThrow()));
    }

    @Test
    void sameMessageIsNeverDeliveredTwiceAcrossReconnect() throws Exception {
        client.send("once".getBytes(StandardCharsets.UTF_8));
        // 截留并重放两次（同一会话代内）。
        clientWire.stopForwarding();
        client.send("once-copy".getBytes(StandardCharsets.UTF_8));
        byte[] copy = clientWire.lastSent();
        clientWire.resumeForwarding();
        clientWire.injectRaw(copy);
        clientWire.injectRaw(copy);

        assertEquals("once", payload(server.pollMessage().orElseThrow()));
        assertEquals("once-copy", payload(server.pollMessage().orElseThrow()));
        assertTrue(server.pollMessage().isEmpty());
        assertEquals(1, server.stats().rejected(RejectReason.DUPLICATE));

        // 重连后再重放：同样不得交付。
        InterceptingTransport wire2 = reconnect();
        wire2.injectRaw(copy);
        assertTrue(server.pollMessage().isEmpty());
        assertEquals(2, server.stats().accepted());
    }
}
