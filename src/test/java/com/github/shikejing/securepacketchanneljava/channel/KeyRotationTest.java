package com.github.shikejing.securepacketchanneljava.channel;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class KeyRotationTest {

    private static final ChannelConfig CONFIG = ChannelConfig.builder()
            .replayWindowSize(64).maxInFlight(16).timeoutMillis(100).maxRetries(2).build();

    @Test
    void rotationCommitsOnBothSides() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{1}, new byte[]{2});
        long sid = w.establish();
        w.a.send(sid, "before".getBytes());
        assertArrayEquals("before".getBytes(), w.b.poll(sid));

        w.a.rotate(sid);
        // Synchronous wire: ROTATE -> ROTATE_ACK completes inline.
        assertEquals(SessionState.ESTABLISHED, w.a.stateOf(sid));
        assertEquals(1, epochOf(w.a, sid));
        assertEquals(1, epochOf(w.b, sid));

        w.a.send(sid, "after".getBytes());
        assertArrayEquals("after".getBytes(), w.b.poll(sid));
        w.b.send(sid, "reply".getBytes());
        assertArrayEquals("reply".getBytes(), w.a.poll(sid));
        assertEquals(1L, w.a.stats().rotationsCommitted());
        assertEquals(1L, w.b.stats().rotationsCommitted());
    }

    @Test
    void inFlightOldEpochPacketsAreNotLost() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{3}, new byte[]{4});
        long sid = w.establish();
        // Capture two data frames without delivering them.
        w.abTransform = frame -> null;
        w.a.send(sid, "old-0".getBytes());
        w.a.send(sid, "old-1".getBytes());
        List<byte[]> inFlight = List.copyOf(w.abLog.subList(w.abLog.size() - 2, w.abLog.size()));
        w.abTransform = java.util.function.UnaryOperator.identity();
        // Rotate while the old-epoch packets are still in flight.
        w.a.rotate(sid);
        assertEquals(1, epochOf(w.b, sid));
        // Late arrival of pre-rotation packets: must still be accepted, in order.
        w.replayToB(inFlight.get(0));
        w.replayToB(inFlight.get(1));
        assertArrayEquals("old-0".getBytes(), w.b.poll(sid));
        assertArrayEquals("old-1".getBytes(), w.b.poll(sid));
        // New-epoch traffic continues seamlessly on top.
        w.a.send(sid, "new-2".getBytes());
        assertArrayEquals("new-2".getBytes(), w.b.poll(sid));
    }

    @Test
    void rotationRollsBackWhenAckNeverArrives() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{5}, new byte[]{6});
        long sid = w.establish();
        // Drop everything a -> b so ROTATE and its retransmits never land.
        w.abTransform = frame -> null;
        w.a.rotate(sid);
        assertEquals(SessionState.ROTATING, w.a.stateOf(sid));
        for (int i = 0; i < 3; i++) {
            clock.advance(100);
            w.a.tick();
        }
        // Rolled back to the old epoch; session is still usable.
        assertEquals(SessionState.ESTABLISHED, w.a.stateOf(sid));
        assertEquals(0, epochOf(w.a, sid));
        assertEquals(1L, w.a.stats().rotationsRolledBack());
        assertEquals(0, epochOf(w.b, sid));

        w.abTransform = java.util.function.UnaryOperator.identity();
        w.a.send(sid, "still works".getBytes());
        assertArrayEquals("still works".getBytes(), w.b.poll(sid));
    }

    @Test
    void rotationRetriesThenCommits() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{7}, new byte[]{8});
        long sid = w.establish();
        boolean[] drop = {true};
        w.abTransform = frame -> drop[0] ? null : frame;
        w.a.rotate(sid);
        assertEquals(SessionState.ROTATING, w.a.stateOf(sid));
        drop[0] = false;
        clock.advance(100);
        w.a.tick(); // retransmitted ROTATE goes through
        assertEquals(SessionState.ESTABLISHED, w.a.stateOf(sid));
        assertEquals(1, epochOf(w.a, sid));
        assertEquals(1, epochOf(w.b, sid));
    }

    @Test
    void tamperedRotateIsIntegrityFailureNotHandshakeFailure() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{9}, new byte[]{10});
        long sid = w.establish();
        w.abTransform = frame -> {
            if ((frame[0] & 0xFF) == PacketType.ROTATE.code()) {
                byte[] f = frame.clone();
                f[f.length - 1] ^= 0x01;
                return f;
            }
            return frame;
        };
        w.a.rotate(sid);
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.INTEGRITY_FAILURE, 0L));
        assertTrue(w.b.stats().handshakeFailureSnapshot().isEmpty());
        // Initiator eventually rolls back; the session survives.
        for (int i = 0; i < 3; i++) {
            clock.advance(100);
            w.a.tick();
        }
        assertEquals(SessionState.ESTABLISHED, w.a.stateOf(sid));
        w.abTransform = java.util.function.UnaryOperator.identity();
        w.a.send(sid, "ok".getBytes());
        assertArrayEquals("ok".getBytes(), w.b.poll(sid));
    }

    @Test
    void keysActuallyChangeAcrossRotation() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{11}, new byte[]{12});
        long sid = w.establish();
        w.a.send(sid, "same-plaintext".getBytes());
        byte[] before = w.abLog.get(w.abLog.size() - 1);
        w.a.rotate(sid);
        w.a.send(sid, "same-plaintext".getBytes());
        byte[] after = w.abLog.get(w.abLog.size() - 1);
        // Same plaintext, different epoch -> different ciphertext and header.
        assertFalse(java.util.Arrays.equals(before, after));
        assertNotEquals(before[12], after[12]); // low byte of epoch changed
    }

    private static int epochOf(SecureChannelEndpoint ep, long sid) {
        return ep.epochOf(sid);
    }
}
