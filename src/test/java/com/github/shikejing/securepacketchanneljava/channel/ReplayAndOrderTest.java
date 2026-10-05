package com.github.shikejing.securepacketchanneljava.channel;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReplayAndOrderTest {

    private static final ChannelConfig CONFIG = ChannelConfig.builder()
            .replayWindowSize(64).maxInFlight(8).build();

    @Test
    void duplicatePacketIsRejectedAsReplay() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{1}, new byte[]{2});
        long sid = w.establish();
        w.a.send(sid, "m0".getBytes());
        byte[] frame = w.abLog.get(w.abLog.size() - 1);
        assertArrayEquals("m0".getBytes(), w.b.poll(sid));
        // Bit-exact replay of the same frame.
        w.replayToB(frame);
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.REPLAY_DUPLICATE, 0L));
        // Not delivered twice.
        assertNull(w.b.poll(sid));
        assertEquals(1L, w.b.stats().accepted());
    }

    @Test
    void outOfOrderWithinWindowIsDeliveredInOrder() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{3}, new byte[]{4});
        long sid = w.establish();
        // Capture frames instead of delivering them.
        w.abTransform = frame -> null;
        w.a.send(sid, "m0".getBytes());
        w.a.send(sid, "m1".getBytes());
        w.a.send(sid, "m2".getBytes());
        List<byte[]> frames = new ArrayList<>(w.abLog.subList(w.abLog.size() - 3, w.abLog.size()));
        w.abTransform = java.util.function.UnaryOperator.identity();
        // Deliver m2, m0, m1 out of order.
        w.replayToB(frames.get(2));
        assertNull(w.b.poll(sid)); // m0 missing: nothing delivered yet
        w.replayToB(frames.get(0));
        assertArrayEquals("m0".getBytes(), w.b.poll(sid));
        assertNull(w.b.poll(sid)); // m1 still missing
        w.replayToB(frames.get(1));
        assertArrayEquals("m1".getBytes(), w.b.poll(sid));
        assertArrayEquals("m2".getBytes(), w.b.poll(sid));
        assertNull(w.b.poll(sid));
        assertEquals(3L, w.b.stats().accepted());
    }

    @Test
    void tooOldPacketIsRejectedForever() {
        MutableClock clock = new MutableClock(0);
        ChannelConfig cfg = ChannelConfig.builder().replayWindowSize(4).maxInFlight(64).build();
        Wire w = Wire.pair(cfg, clock, new byte[]{5}, new byte[]{6});
        long sid = w.establish();
        w.abTransform = frame -> null;
        for (int i = 0; i < 6; i++) {
            w.a.send(sid, ("m" + i).getBytes());
        }
        List<byte[]> frames = new ArrayList<>(w.abLog.subList(w.abLog.size() - 6, w.abLog.size()));
        w.abTransform = java.util.function.UnaryOperator.identity();
        // Deliver m5 first: window slides to [2..5]; m0 and m1 are now too old.
        w.replayToB(frames.get(5));
        w.replayToB(frames.get(0));
        w.replayToB(frames.get(1));
        assertEquals(2L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.TOO_OLD, 0L));
        // Replaying them again must still fail, never accepted again.
        w.replayToB(frames.get(0));
        assertEquals(3L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.TOO_OLD, 0L));
        // m2..m4 still arrive and are delivered in order.
        w.replayToB(frames.get(2));
        w.replayToB(frames.get(3));
        w.replayToB(frames.get(4));
        assertArrayEquals("m2".getBytes(), w.b.poll(sid));
        assertArrayEquals("m3".getBytes(), w.b.poll(sid));
        assertArrayEquals("m4".getBytes(), w.b.poll(sid));
        assertArrayEquals("m5".getBytes(), w.b.poll(sid));
    }

    @Test
    void replayWindowUnitSemantics() {
        ReplayWindow win = new ReplayWindow(4);
        assertEquals(ReplayWindow.Verdict.ACCEPTED, win.checkAndMark(0));
        assertEquals(ReplayWindow.Verdict.DUPLICATE, win.checkAndMark(0));
        assertEquals(ReplayWindow.Verdict.ACCEPTED, win.checkAndMark(3));
        assertEquals(ReplayWindow.Verdict.ACCEPTED, win.checkAndMark(2));
        assertEquals(ReplayWindow.Verdict.DUPLICATE, win.checkAndMark(2));
        assertEquals(ReplayWindow.Verdict.ACCEPTED, win.checkAndMark(4));
        // Window is now [1..4]; 0 fell behind.
        assertEquals(ReplayWindow.Verdict.TOO_OLD, win.checkAndMark(0));
        // Big jump clears the window.
        assertEquals(ReplayWindow.Verdict.ACCEPTED, win.checkAndMark(100));
        assertEquals(ReplayWindow.Verdict.TOO_OLD, win.checkAndMark(4));
    }

    @Test
    void bufferOverflowIsRejectedDistinctly() {
        MutableClock clock = new MutableClock(0);
        ChannelConfig cfg = ChannelConfig.builder().replayWindowSize(64).maxInFlight(4).build();
        Wire w = Wire.pair(cfg, clock, new byte[]{7}, new byte[]{8});
        long sid = w.establish();
        w.abTransform = frame -> null;
        for (int i = 0; i < 6; i++) {
            w.a.send(sid, ("m" + i).getBytes());
        }
        List<byte[]> frames = new ArrayList<>(w.abLog.subList(w.abLog.size() - 6, w.abLog.size()));
        w.abTransform = java.util.function.UnaryOperator.identity();
        // Deliver m5 first: 5 - 0 >= maxInFlight(4) -> BUFFER_OVERFLOW, not marked.
        w.replayToB(frames.get(5));
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.BUFFER_OVERFLOW, 0L));
        // Drain m0..m4 so the delivery point advances...
        for (int i = 0; i < 5; i++) {
            w.replayToB(frames.get(i));
            assertArrayEquals(("m" + i).getBytes(), w.b.poll(sid));
        }
        // ...then a resent m5 fits the buffer bound and is accepted.
        w.replayToB(frames.get(5));
        assertArrayEquals("m5".getBytes(), w.b.poll(sid));
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.BUFFER_OVERFLOW, 0L));
    }
}
