package com.github.shikejing.securepacketchanneljava.channel;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HandshakeTest {

    private static final ChannelConfig CONFIG = ChannelConfig.defaults();

    @Test
    void happyPathEstablishesBothSides() {
        MutableClock clock = new MutableClock(1_000);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{1}, new byte[]{2});
        long sessionId = w.establish();
        assertEquals(SessionState.ESTABLISHED, w.a.stateOf(sessionId));
        assertEquals(SessionState.ESTABLISHED, w.b.stateOf(sessionId));
        assertEquals(1, w.a.stats().handshakesCompleted());
        assertEquals(1, w.b.stats().handshakesCompleted());
    }

    @Test
    void tamperedHello2FailsWithTranscriptMismatch() {
        MutableClock clock = new MutableClock(1_000);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{3}, new byte[]{4});
        // Flip one bit in the server's public key inside HELLO2.
        w.baTransform = frame -> {
            byte[] f = frame.clone();
            f[Packet.HEADER_LEN + 20] ^= 0x01;
            return f;
        };
        HandshakeHandle h = w.a.connect();
        assertTrue(h.isDone());
        assertEquals(HandshakeFailure.TRANSCRIPT_MISMATCH, h.failure());
        assertTrue(h.sessionId().isEmpty());
        assertEquals(1L, w.a.stats().handshakeFailureSnapshot()
                .getOrDefault(HandshakeFailure.TRANSCRIPT_MISMATCH, 0L));
    }

    @Test
    void versionMismatchIsReportedDistinctly() {
        MutableClock clock = new MutableClock(1_000);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{5}, new byte[]{6});
        // Corrupt the version byte of the client's HELLO.
        w.abTransform = frame -> {
            byte[] f = frame.clone();
            f[Packet.HEADER_LEN] = 99;
            return f;
        };
        HandshakeHandle h = w.a.connect();
        assertTrue(h.isDone());
        assertEquals(HandshakeFailure.VERSION_MISMATCH, h.failure());
        // Negotiation failures must not be conflated with integrity failures.
        assertFalse(w.a.stats().rejectedSnapshot().containsKey(RejectReason.INTEGRITY_FAILURE));
    }

    @Test
    void droppedHelloExhaustsRetries() {
        MutableClock clock = new MutableClock(1_000);
        ChannelConfig config = ChannelConfig.builder().timeoutMillis(100).maxRetries(2).build();
        Wire w = Wire.pair(config, clock, new byte[]{7}, new byte[]{8});
        w.abTransform = frame -> null; // black hole
        HandshakeHandle h = w.a.connect();
        assertFalse(h.isDone());
        clock.advance(100);
        w.a.tick(); // retry 1
        assertFalse(h.isDone());
        clock.advance(100);
        w.a.tick(); // retry 2
        assertFalse(h.isDone());
        clock.advance(100);
        w.a.tick(); // budget exhausted
        assertTrue(h.isDone());
        assertEquals(HandshakeFailure.RETRIES_EXHAUSTED, h.failure());
    }

    @Test
    void retryRecoversWhenDropsStop() {
        MutableClock clock = new MutableClock(1_000);
        ChannelConfig config = ChannelConfig.builder().timeoutMillis(100).maxRetries(3).build();
        Wire w = Wire.pair(config, clock, new byte[]{9}, new byte[]{10});
        boolean[] drop = {true};
        w.abTransform = frame -> drop[0] ? null : frame;
        HandshakeHandle h = w.a.connect();
        assertFalse(h.isDone());
        drop[0] = false;
        clock.advance(100);
        w.a.tick(); // retransmitted HELLO gets through
        assertTrue(h.isDone());
        assertTrue(h.sessionId().isPresent());
        assertEquals(SessionState.ESTABLISHED, w.a.stateOf(h.sessionId().getAsLong()));
    }

    @Test
    void fixedSeedsYieldIdenticalSessionIds() {
        MutableClock c1 = new MutableClock(1_000);
        Wire w1 = Wire.pair(CONFIG, c1, new byte[]{11}, new byte[]{12});
        long id1 = w1.establish();
        MutableClock c2 = new MutableClock(1_000);
        Wire w2 = Wire.pair(CONFIG, c2, new byte[]{11}, new byte[]{12});
        long id2 = w2.establish();
        assertEquals(id1, id2);
        // And the wire bytes are identical too.
        assertEquals(w1.abLog.size(), w2.abLog.size());
        for (int i = 0; i < w1.abLog.size(); i++) {
            assertArrayEquals(w1.abLog.get(i), w2.abLog.get(i));
        }
    }
}
