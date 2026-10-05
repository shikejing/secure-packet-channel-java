package com.github.shikejing.securepacketchanneljava.channel;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class ConcurrencyIsolationTest {

    private static final ChannelConfig CONFIG = ChannelConfig.builder()
            .replayWindowSize(128).maxInFlight(64).build();

    @Test
    void hostileSessionDoesNotAffectOthers() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{1}, new byte[]{2});
        long good1 = w.establish();
        long good2 = w.establish();

        // Flood endpoint b with garbage aimed at a non-existent session and
        // malformed frames, interleaved with valid traffic on good sessions.
        for (int i = 0; i < 100; i++) {
            w.replayToB(new byte[]{(byte) 0x55, 1, 2, 3});
            w.replayToB(PacketCodec.encode(new Packet(PacketType.DATA, 999999L, 0, i, new byte[20])));
            w.a.send(good1, ("g1-" + i).getBytes());
            w.a.send(good2, ("g2-" + i).getBytes());
            // Drain as we go so the in-flight bound is never the reason for loss.
            assertArrayEquals(("g1-" + i).getBytes(), w.b.poll(good1));
            assertArrayEquals(("g2-" + i).getBytes(), w.b.poll(good2));
        }
        assertEquals(200L, w.b.stats().accepted());
        assertTrue(w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.UNKNOWN_SESSION, 0L) >= 100);
    }

    @Test
    void closedSessionDropsDoNotBlockOtherSessions() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{3}, new byte[]{4});
        long victim = w.establish();
        long survivor = w.establish();
        w.a.close(victim);
        // Everything for the closed session is rejected...
        Packet forged = new Packet(PacketType.DATA, victim, 0, 0, new byte[16]);
        w.replayToB(PacketCodec.encode(forged));
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.STALE_SESSION, 0L));
        // ...while the surviving session keeps working.
        w.a.send(survivor, "still here".getBytes());
        assertArrayEquals("still here".getBytes(), w.b.poll(survivor));
    }

    @Test
    void concurrentSessionsSendAndReceive() throws Exception {
        MutableClock clock = new MutableClock(0);
        // Deliveries happen on the caller thread; the wire is just a method
        // call, so this exercises the endpoint's internal locking directly.
        Wire w = Wire.pair(CONFIG, clock, new byte[]{5}, new byte[]{6});
        int sessionCount = 8;
        int messagesPerSession = 50;
        List<Long> sids = new ArrayList<>();
        for (int i = 0; i < sessionCount; i++) {
            sids.add(w.establish());
        }
        ExecutorService pool = Executors.newFixedThreadPool(sessionCount);
        CountDownLatch done = new CountDownLatch(sessionCount);
        for (int s = 0; s < sessionCount; s++) {
            final long sid = sids.get(s);
            final int tag = s;
            pool.submit(() -> {
                try {
                    for (int m = 0; m < messagesPerSession; m++) {
                        w.a.send(sid, (tag + ":" + m).getBytes());
                    }
                } finally {
                    done.countDown();
                }
            });
        }
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();
        // Every session must deliver exactly its own messages, in order.
        for (int s = 0; s < sessionCount; s++) {
            long sid = sids.get(s);
            for (int m = 0; m < messagesPerSession; m++) {
                byte[] msg = w.b.poll(sid);
                assertNotNull(msg, "session " + s + " missing message " + m);
                assertEquals(s + ":" + m, new String(msg));
            }
            assertNull(w.b.poll(sid));
        }
        assertEquals((long) sessionCount * messagesPerSession, w.b.stats().accepted());
    }

    @Test
    void concurrentRotationAndTrafficStaysConsistent() throws Exception {
        MutableClock clock = new MutableClock(0);
        // Large in-flight bound: the upper layer only polls after the senders
        // finish, so the receiver must be able to hold everything.
        ChannelConfig cfg = ChannelConfig.builder()
                .replayWindowSize(1024).maxInFlight(4096).build();
        Wire w = Wire.pair(cfg, clock, new byte[]{7}, new byte[]{8});
        long sid = w.establish();
        int messages = 200;
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch done = new CountDownLatch(2);
        pool.submit(() -> {
            try {
                for (int i = 0; i < messages; i++) {
                    w.a.send(sid, ("m" + i).getBytes());
                }
            } finally {
                done.countDown();
            }
        });
        pool.submit(() -> {
            try {
                for (int i = 0; i < 5; i++) {
                    w.a.rotate(sid);
                }
            } finally {
                done.countDown();
            }
        });
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();
        // All messages arrive exactly once and in order, across rotations.
        for (int i = 0; i < messages; i++) {
            byte[] msg = w.b.poll(sid);
            assertNotNull(msg, "missing message " + i);
            assertEquals("m" + i, new String(msg));
        }
        assertNull(w.b.poll(sid));
        assertEquals(epochOf(w.a, sid), epochOf(w.b, sid));
    }

    private static int epochOf(SecureChannelEndpoint ep, long sid) {
        return ep.epochOf(sid);
    }
}
