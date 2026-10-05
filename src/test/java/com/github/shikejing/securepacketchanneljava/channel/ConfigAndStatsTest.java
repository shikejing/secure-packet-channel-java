package com.github.shikejing.securepacketchanneljava.channel;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ConfigAndStatsTest {

    @Test
    void configChangeAffectsOnlySubsequentPackets() {
        MutableClock clock = new MutableClock(0);
        ChannelConfig cfg = ChannelConfig.builder().replayWindowSize(64).maxInFlight(4).build();
        Wire w = Wire.pair(cfg, clock, new byte[]{1}, new byte[]{2});
        long sid = w.establish();

        // With maxInFlight=4, a packet 10 ahead of the delivery point overflows.
        w.abTransform = frame -> null;
        for (int i = 0; i <= 10; i++) {
            w.a.send(sid, ("m" + i).getBytes());
        }
        java.util.List<byte[]> frames = new java.util.ArrayList<>(w.abLog.subList(w.abLog.size() - 11, w.abLog.size()));
        w.abTransform = java.util.function.UnaryOperator.identity();
        w.replayToB(frames.get(10));
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.BUFFER_OVERFLOW, 0L));

        // Enlarge the bound: the same relative distance is now accepted.
        w.b.updateConfig(ChannelConfig.builder().replayWindowSize(64).maxInFlight(64).build());
        w.replayToB(frames.get(10));
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.BUFFER_OVERFLOW, 0L));
        assertEquals(1L, w.b.stats().accepted());
    }

    @Test
    void configValidationRejectsNonsense() {
        assertThrows(IllegalArgumentException.class,
                () -> ChannelConfig.builder().replayWindowSize(0).build());
        assertThrows(IllegalArgumentException.class,
                () -> ChannelConfig.builder().maxInFlight(-1).build());
        assertThrows(IllegalArgumentException.class,
                () -> ChannelConfig.builder().timeoutMillis(0).build());
    }

    @Test
    void statsAreObservableAndClassified() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(ChannelConfig.defaults(), clock, new byte[]{3}, new byte[]{4});
        long sid = w.establish();
        w.a.send(sid, "ok".getBytes());
        byte[] frame = w.abLog.get(w.abLog.size() - 1);
        assertArrayEquals("ok".getBytes(), w.b.poll(sid));
        w.replayToB(frame);               // duplicate
        w.replayToB(new byte[]{9});       // malformed
        w.replayToB(frame.clone());       // duplicate again

        assertEquals(1L, w.b.stats().accepted());
        assertEquals(2L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.REPLAY_DUPLICATE, 0L));
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.MALFORMED_PACKET, 0L));
        assertEquals(1L, w.b.stats().handshakesCompleted());
    }
}
