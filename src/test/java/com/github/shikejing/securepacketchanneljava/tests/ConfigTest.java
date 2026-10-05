package com.github.shikejing.securepacketchanneljava.tests;

import com.github.shikejing.securepacketchanneljava.channel.ChannelConfig;
import com.github.shikejing.securepacketchanneljava.channel.ChannelStats;
import com.github.shikejing.securepacketchanneljava.channel.CryptoUtil;
import com.github.shikejing.securepacketchanneljava.channel.LoopbackTransport;
import com.github.shikejing.securepacketchanneljava.channel.Message;
import com.github.shikejing.securepacketchanneljava.channel.RejectReason;
import com.github.shikejing.securepacketchanneljava.channel.SecureSession;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/** 可配置项：窗口、在途缓冲上界、超时与重试；配置变更有界；统计可观测。 */
class ConfigTest {

    @Test
    void invalidConfigIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ChannelConfig.builder().replayWindowSize(0));
        assertThrows(IllegalArgumentException.class, () -> ChannelConfig.builder().replayWindowSize(ChannelConfig.MAX_WINDOW_SIZE + 1));
        assertThrows(IllegalArgumentException.class, () -> ChannelConfig.builder().maxInFlight(0));
        assertThrows(IllegalArgumentException.class, () -> ChannelConfig.builder().handshakeTimeoutMillis(0));
        assertThrows(IllegalArgumentException.class, () -> ChannelConfig.builder().maxHandshakeRetries(-1));
        assertThrows(IllegalArgumentException.class, () -> ChannelConfig.builder().rotationIntervalMillis(0));
    }

    @Test
    void inFlightBufferBoundDropsBurstAndReportsStats() throws Exception {
        LoopbackTransport[] link = LoopbackTransport.pair();
        ChannelConfig cfg = ChannelConfig.builder().maxInFlight(2).build();
        SecureSession client = SecureSession.client(1L, link[0], cfg, CryptoUtil.deterministicRandom(1L));
        SecureSession server = SecureSession.server(1L, link[1], cfg, CryptoUtil.deterministicRandom(2L));
        client.startHandshake();
        server.accept();
        client.completeHandshake();

        // 突发 5 条：交付队列上界 2，其余以 BUFFER_FULL 拒绝，会话不停在半处理状态。
        for (int i = 0; i < 5; i++) {
            client.send(("b" + i).getBytes(StandardCharsets.UTF_8));
        }
        List<String> delivered = new ArrayList<>();
        Optional<Message> m;
        while ((m = server.pollMessage()).isPresent()) {
            delivered.add(new String(m.get().payload(), StandardCharsets.UTF_8));
        }
        assertEquals(List.of("b0", "b1"), delivered);
        ChannelStats.Snapshot stats = server.stats();
        assertEquals(2, stats.accepted());
        assertEquals(3, stats.rejected(RejectReason.BUFFER_FULL));
        assertEquals(SecureSession.State.ESTABLISHED, server.state());

        // 队列排空后，后续报文照常接收：拒绝只影响当时超限的报文。
        client.send("after".getBytes(StandardCharsets.UTF_8));
        assertEquals("after", new String(server.pollMessage().orElseThrow().payload(), StandardCharsets.UTF_8));
    }

    @Test
    void statsAreObservableAndConsistent() throws Exception {
        LoopbackTransport[] link = LoopbackTransport.pair();
        InterceptingTransport wire = new InterceptingTransport(link[0]);
        SecureSession client = SecureSession.client(1L, wire, ChannelConfig.defaults(), CryptoUtil.deterministicRandom(1L));
        SecureSession server = SecureSession.server(1L, link[1], ChannelConfig.defaults(), CryptoUtil.deterministicRandom(2L));
        client.startHandshake();
        server.accept();
        client.completeHandshake();
        wire.clearSent();

        client.send("ok".getBytes(StandardCharsets.UTF_8));
        wire.injectRaw(new byte[]{1, 2, 3}); // 垃圾报文
        server.pollMessage();
        server.pollMessage();

        ChannelStats.Snapshot s = server.stats();
        assertEquals(1, s.accepted());
        assertEquals(1, s.rejected(RejectReason.MALFORMED));
        assertEquals(1, s.totalRejected());
        assertEquals(0, client.stats().sent() - 1, "客户端只发出一条数据报文");
        // 快照是副本：后续变化不影响已取快照。
        client.send("more".getBytes(StandardCharsets.UTF_8));
        server.pollMessage();
        assertEquals(1, s.accepted());
        assertEquals(2, server.stats().accepted());
    }

    @Test
    void configChangeAppliesAtomicallyToSubsequentPackets() throws Exception {
        LoopbackTransport[] link = LoopbackTransport.pair();
        ChannelConfig initial = ChannelConfig.defaults();
        SecureSession client = SecureSession.client(1L, link[0], initial, CryptoUtil.deterministicRandom(1L));
        SecureSession server = SecureSession.server(1L, link[1], initial, CryptoUtil.deterministicRandom(2L));
        client.startHandshake();
        server.accept();
        client.completeHandshake();

        ChannelConfig updated = ChannelConfig.builder().replayWindowSize(4).maxInFlight(8).build();
        server.updateConfig(updated);
        // 变更后会话仍然自洽可用。
        client.send("x".getBytes(StandardCharsets.UTF_8));
        assertEquals("x", new String(server.pollMessage().orElseThrow().payload(), StandardCharsets.UTF_8));
        assertEquals(SecureSession.State.ESTABLISHED, server.state());
    }
}
