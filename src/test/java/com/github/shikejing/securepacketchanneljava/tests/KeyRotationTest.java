package com.github.shikejing.securepacketchanneljava.tests;

import com.github.shikejing.securepacketchanneljava.channel.ChannelConfig;
import com.github.shikejing.securepacketchanneljava.channel.CryptoUtil;
import com.github.shikejing.securepacketchanneljava.channel.LoopbackTransport;
import com.github.shikejing.securepacketchanneljava.channel.Message;
import com.github.shikejing.securepacketchanneljava.channel.SecureSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/** 密钥轮换：切换过程在途报文不丢失，边界明确，失败可回退且会话继续。 */
class KeyRotationTest {

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

    @Test
    void rotationSwitchesKeysWithoutLosingInFlightPackets() {
        client.send("before".getBytes(StandardCharsets.UTF_8));
        assertTrue(client.initiateRotation());
        client.send("during".getBytes(StandardCharsets.UTF_8)); // 发起方提交前仍用旧密钥

        Message before = server.pollMessage().orElseThrow();
        assertEquals("before", payload(before));
        assertEquals(0, before.keyEpoch());

        Message during = server.pollMessage().orElseThrow(); // 内部先处理 ROTATE
        assertEquals("during", payload(during));
        assertEquals(0, during.keyEpoch());

        client.pollMessage(); // 处理 COMMIT，完成轮换
        assertEquals(SecureSession.State.ESTABLISHED, client.state());
        assertEquals(1, client.stats().rotations());
        assertEquals(1, client.currentSendEpoch());

        client.send("after".getBytes(StandardCharsets.UTF_8));
        Message after = server.pollMessage().orElseThrow();
        assertEquals("after", payload(after));
        assertEquals(1, after.keyEpoch(), "切换边界之后必须使用新密钥代");

        // 对端（接收方）在 ROTATE 后即切到新发送密钥代，双向都可用。
        server.send("reply".getBytes(StandardCharsets.UTF_8));
        Message reply = client.pollMessage().orElseThrow();
        assertEquals("reply", payload(reply));
        assertEquals(1, reply.keyEpoch());
        assertEquals(3, server.stats().accepted());
        assertEquals(0, server.stats().totalRejected());
    }

    @Test
    void oldEpochPacketsInFlightAreAcceptedAfterRotation() {
        // 轮换前发出的报文被截留，轮换完成后才到达：不得丢失。
        clientWire.stopForwarding();
        client.send("in-flight".getBytes(StandardCharsets.UTF_8));
        byte[] inFlight = clientWire.lastSent();
        clientWire.clearSent();
        clientWire.resumeForwarding();

        assertTrue(client.initiateRotation());
        server.pollMessage();   // 处理 ROTATE
        client.pollMessage();   // 处理 COMMIT
        assertEquals(1, client.currentSendEpoch());

        clientWire.injectRaw(inFlight); // 旧密钥代的在途报文迟到
        Message m = server.pollMessage().orElseThrow();
        assertEquals("in-flight", payload(m));
        assertEquals(0, m.keyEpoch());
        assertEquals(0, server.stats().totalRejected());
    }

    @Test
    void abortedRotationRollsBackAndSessionContinues() {
        client.send("pre".getBytes(StandardCharsets.UTF_8));
        assertEquals("pre", payload(server.pollMessage().orElseThrow()));

        assertTrue(client.initiateRotation());
        assertEquals(SecureSession.State.ROTATING, client.state());
        assertTrue(client.abortRotation()); // 轮换失败/取消：回退到上一代密钥

        // 双方都消化控制报文。
        server.pollMessage(); // ROTATE 然后 ABORT
        client.pollMessage(); // COMMIT（已中止，忽略）

        assertEquals(SecureSession.State.ESTABLISHED, client.state());
        assertEquals(SecureSession.State.ESTABLISHED, server.state());
        assertEquals(0, client.currentSendEpoch(), "回退后仍使用上一代密钥");
        assertEquals(1, client.stats().rotationRollbacks());
        assertEquals(1, server.stats().rotationRollbacks());

        // 会话继续：双向收发正常。
        client.send("post".getBytes(StandardCharsets.UTF_8));
        assertEquals("post", payload(server.pollMessage().orElseThrow()));
        server.send("back".getBytes(StandardCharsets.UTF_8));
        assertEquals("back", payload(client.pollMessage().orElseThrow()));
        assertEquals(0, server.stats().totalRejected());
        assertEquals(0, client.stats().totalRejected());
    }

    @Test
    void successiveRotationsAdvanceEpochs() {
        for (int epoch = 1; epoch <= 3; epoch++) {
            assertTrue(client.initiateRotation());
            server.pollMessage();
            client.pollMessage();
            assertEquals(epoch, client.currentSendEpoch());
            client.send(("e" + epoch).getBytes(StandardCharsets.UTF_8));
            Message m = server.pollMessage().orElseThrow();
            assertEquals(epoch, m.keyEpoch());
        }
        assertEquals(3, client.stats().rotations());
        assertEquals(0, server.stats().totalRejected());
    }
}
