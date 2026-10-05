package com.github.shikejing.securepacketchanneljava.channel;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Requirement: with a fixed seed and the same input sequence, the receive
 * results must match message for message, so historical issues replay.
 */
class DeterminismTest {

    private static final ChannelConfig CONFIG = ChannelConfig.builder()
            .replayWindowSize(32).maxInFlight(64).timeoutMillis(50).maxRetries(2).build();

    /** A scripted run: handshake, traffic, rotation, drop+retry, reconnect. */
    private static List<String> scriptedRun(List<byte[]> wireTap) {
        MutableClock clock = new MutableClock(42);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{42}, new byte[]{43});
        List<String> delivered = new ArrayList<>();

        long sid = w.establish();
        for (int i = 0; i < 10; i++) {
            w.a.send(sid, ("phase1-" + i).getBytes());
        }
        drain(w, sid, delivered);

        w.a.rotate(sid);
        for (int i = 0; i < 5; i++) {
            w.a.send(sid, ("phase2-" + i).getBytes());
            w.b.send(sid, ("reply-" + i).getBytes());
        }
        drain(w, sid, delivered);
        for (int i = 0; i < 5; i++) {
            delivered.add("a<-" + new String(w.a.poll(sid)));
        }

        // Drop one data frame, then let the window slide past it.
        w.abTransform = frame -> (frame[0] & 0xFF) == PacketType.DATA.code() ? null : frame;
        w.a.send(sid, "lost".getBytes());
        w.abTransform = java.util.function.UnaryOperator.identity();
        for (int i = 0; i < 40; i++) {
            w.a.send(sid, ("phase3-" + i).getBytes());
        }
        drain(w, sid, delivered);

        w.a.close(sid);
        long sid2 = w.establish();
        w.a.send(sid2, "after-reconnect".getBytes());
        drain(w, sid2, delivered);

        wireTap.addAll(w.abLog);
        wireTap.addAll(w.baLog);
        return delivered;
    }

    private static void drain(Wire w, long sid, List<String> out) {
        byte[] msg;
        while ((msg = w.b.poll(sid)) != null) {
            out.add(new String(msg));
        }
    }

    @Test
    void sameSeedSameInputsSameOutputs() {
        List<byte[]> wire1 = new ArrayList<>();
        List<String> run1 = scriptedRun(wire1);
        List<byte[]> wire2 = new ArrayList<>();
        List<String> run2 = scriptedRun(wire2);

        // Delivered message sequences are identical, message for message.
        assertEquals(run1, run2);
        assertFalse(run1.isEmpty());
        // And every byte on the wire is identical.
        assertEquals(wire1.size(), wire2.size());
        for (int i = 0; i < wire1.size(); i++) {
            assertArrayEquals(wire1.get(i), wire2.get(i), "wire frame " + i + " differs");
        }
    }

    @Test
    void lostMessageIsSkippedDeterministically() {
        List<String> run = scriptedRun(new ArrayList<>());
        assertFalse(run.contains("lost"));
        assertTrue(run.contains("phase3-0"));
        assertTrue(run.contains("after-reconnect"));
    }
}
