package com.github.shikejing.securepacketchanneljava.tests;

import com.github.shikejing.securepacketchanneljava.channel.ChannelConfig;
import com.github.shikejing.securepacketchanneljava.channel.CryptoUtil;
import com.github.shikejing.securepacketchanneljava.channel.LoopbackTransport;
import com.github.shikejing.securepacketchanneljava.channel.Message;
import com.github.shikejing.securepacketchanneljava.channel.RejectReason;
import com.github.shikejing.securepacketchanneljava.channel.SecureSession;
import com.github.shikejing.securepacketchanneljava.channel.SessionManager;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** 多会话并发收发：单会话的异常输入或掉线不影响其他会话，状态始终自洽。 */
class ConcurrencyTest {

    private static SecureSession[] pair(long id, long seedA, long seedB) {
        return SessionManager.establishedPair(id, ChannelConfig.builder().maxInFlight(1024).build(), seedA, seedB);
    }

    @Test
    void manySessionsExchangeConcurrentlyWithoutCrossTalk() throws Exception {
        int sessions = 4;
        int perSession = 50;
        SecureSession[][] pairs = new SecureSession[sessions][];
        SessionManager manager = new SessionManager();
        for (int i = 0; i < sessions; i++) {
            pairs[i] = pair(1000L + i, 10L + i, 20L + i);
            assertTrue(manager.register(pairs[i][1])); // 注册服务端端点；同对的两个端点共享会话标识
        }

        ExecutorService pool = Executors.newFixedThreadPool(sessions * 2);
        CountDownLatch done = new CountDownLatch(sessions * 2);
        for (int i = 0; i < sessions; i++) {
            final int idx = i;
            SecureSession client = pairs[i][0];
            SecureSession server = pairs[i][1];
            pool.submit(() -> {
                try {
                    for (int m = 0; m < perSession; m++) {
                        client.send(("s" + idx + "-m" + m).getBytes(StandardCharsets.UTF_8));
                    }
                } finally {
                    done.countDown();
                }
            });
            pool.submit(() -> {
                try {
                    List<String> got = new ArrayList<>();
                    long deadline = System.currentTimeMillis() + 10_000;
                    while (got.size() < perSession && System.currentTimeMillis() < deadline) {
                        Optional<Message> m = server.pollMessage();
                        m.ifPresent(msg -> got.add(new String(msg.payload(), StandardCharsets.UTF_8)));
                        if (m.isEmpty()) Thread.yield();
                    }
                    assertEquals(perSession, got.size(), "session " + idx + " lost messages");
                    for (int m = 0; m < perSession; m++) {
                        assertEquals("s" + idx + "-m" + m, got.get(m), "session " + idx + " misordered");
                    }
                } finally {
                    done.countDown();
                }
            });
        }
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdownNow();

        // 每个会话：发送数 == 接受数，无拒绝，无串扰。
        for (int i = 0; i < sessions; i++) {
            assertEquals(perSession, pairs[i][0].stats().sent());
            assertEquals(perSession, pairs[i][1].stats().accepted());
            assertEquals(0, pairs[i][1].stats().totalRejected());
        }
        assertEquals(sessions, manager.sessionIds().size());
    }

    @Test
    void poisonedSessionDoesNotAffectOthers() throws Exception {
        SecureSession[] a = pair(1L, 1L, 2L);
        SecureSession[] b = pair(2L, 3L, 4L);

        // 会话 A 遭遇异常输入：垃圾字节、篡改、重放。
        LoopbackTransport[] linkA = LoopbackTransport.pair();
        InterceptingTransport wireA = new InterceptingTransport(linkA[0]);
        SecureSession clientA = SecureSession.client(11L, wireA, ChannelConfig.defaults(), CryptoUtil.deterministicRandom(11L));
        SecureSession serverA = SecureSession.server(11L, linkA[1], ChannelConfig.defaults(), CryptoUtil.deterministicRandom(12L));
        clientA.startHandshake();
        serverA.accept();
        clientA.completeHandshake();
        wireA.clearSent();

        wireA.stopForwarding();
        clientA.send("valid".getBytes(StandardCharsets.UTF_8));
        byte[] valid = wireA.lastSent();
        byte[] tampered = valid.clone();
        tampered[tampered.length - 1] ^= 0x01;
        wireA.resumeForwarding();
        wireA.injectRaw(new byte[]{9, 9, 9});
        wireA.injectRaw(tampered);
        wireA.injectRaw(valid);
        wireA.injectRaw(valid); // 重放

        // 会话 A 掉线（关闭）。
        clientA.close();

        // 会话 B 全程不受影响。
        b[0].send("b-traffic".getBytes(StandardCharsets.UTF_8));
        assertEquals("b-traffic", new String(b[1].pollMessage().orElseThrow().payload(), StandardCharsets.UTF_8));
        assertEquals(1, b[1].stats().accepted());
        assertEquals(0, b[1].stats().totalRejected());

        // 会话 A 的统计自洽：1 条接受，垃圾/篡改/重放分别归类。
        while (serverA.pollMessage().isPresent()) {
            // 排空
        }
        assertEquals(1, serverA.stats().accepted());
        assertEquals(1, serverA.stats().rejected(RejectReason.MALFORMED));
        assertEquals(1, serverA.stats().rejected(RejectReason.INTEGRITY_FAILURE));
        assertEquals(1, serverA.stats().rejected(RejectReason.DUPLICATE));

        // 关闭后的会话拒绝新输入，且不影响其他会话。
        a[0].close();
        a[1].close();
        b[0].send("still-ok".getBytes(StandardCharsets.UTF_8));
        assertEquals("still-ok", new String(b[1].pollMessage().orElseThrow().payload(), StandardCharsets.UTF_8));
    }

    @Test
    void closedSessionRejectsFurtherInput() throws Exception {
        SecureSession[] p = pair(5L, 5L, 6L);
        p[0].send("before-close".getBytes(StandardCharsets.UTF_8));
        p[1].close();
        assertTrue(p[1].pollMessage().isEmpty());
        assertEquals(1, p[1].stats().rejected(RejectReason.SESSION_CLOSED));
        assertThrows(IllegalStateException.class, () -> p[1].send("x".getBytes(StandardCharsets.UTF_8)));
    }
}
