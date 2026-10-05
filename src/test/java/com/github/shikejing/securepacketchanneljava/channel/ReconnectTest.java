package com.github.shikejing.securepacketchanneljava.channel;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReconnectTest {

    private static final ChannelConfig CONFIG = ChannelConfig.builder()
            .replayWindowSize(64).maxInFlight(16).build();

    @Test
    void reconnectGetsFreshSessionAndRejectsOldPackets() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{1}, new byte[]{2});
        long oldSid = w.establish();
        w.a.send(oldSid, "old-message".getBytes());
        assertArrayEquals("old-message".getBytes(), w.b.poll(oldSid));
        // Capture one old-session frame for later replay.
        w.a.send(oldSid, "old-ghost".getBytes());
        byte[] ghost = w.abLog.get(w.abLog.size() - 1);

        // Disconnect and reconnect.
        w.a.close(oldSid);
        assertEquals(SessionState.CLOSED, w.a.stateOf(oldSid));
        assertEquals(SessionState.CLOSED, w.b.stateOf(oldSid));

        long newSid = w.establish();
        assertNotEquals(oldSid, newSid);
        assertEquals(SessionState.ESTABLISHED, w.a.stateOf(newSid));

        // A packet from the old session must be rejected as STALE_SESSION.
        long before = w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.STALE_SESSION, 0L);
        w.replayToB(ghost);
        assertEquals(before + 1, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.STALE_SESSION, 0L));
        // And nothing leaks into the new session.
        assertNull(w.b.poll(newSid));
    }

    @Test
    void reconnectDoesNotReprocessOrReorder() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{3}, new byte[]{4});
        long sid1 = w.establish();
        for (int i = 0; i < 5; i++) {
            w.a.send(sid1, ("s1-m" + i).getBytes());
        }
        List<byte[]> session1Frames = new ArrayList<>(w.abLog);
        for (int i = 0; i < 5; i++) {
            assertArrayEquals(("s1-m" + i).getBytes(), w.b.poll(sid1));
        }
        w.a.close(sid1);

        long sid2 = w.establish();
        for (int i = 0; i < 3; i++) {
            w.a.send(sid2, ("s2-m" + i).getBytes());
        }
        for (int i = 0; i < 3; i++) {
            assertArrayEquals(("s2-m" + i).getBytes(), w.b.poll(sid2));
        }
        // Replay every session-1 frame: none may be processed a second time.
        long acceptedBefore = w.b.stats().accepted();
        for (byte[] f : session1Frames) {
            w.replayToB(f);
        }
        assertEquals(acceptedBefore, w.b.stats().accepted());
        assertNull(w.b.poll(sid2));
    }

    @Test
    void sequenceNumbersAreMonotonicWithinSession() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{5}, new byte[]{6});
        long sid = w.establish();
        long prevSeq = -1;
        for (int i = 0; i < 10; i++) {
            w.a.send(sid, ("m" + i).getBytes());
            byte[] frame = w.abLog.get(w.abLog.size() - 1);
            Packet p = PacketCodec.decode(frame);
            assertTrue(p.seq() > prevSeq, "sequence must increase monotonically");
            prevSeq = p.seq();
        }
        // Rotation must not reset or jump the sequence space.
        w.a.rotate(sid);
        w.a.send(sid, "after-rotation".getBytes());
        Packet p = PacketCodec.decode(w.abLog.get(w.abLog.size() - 1));
        assertTrue(p.seq() > prevSeq);
        assertEquals(1, p.epoch());
    }

    @Test
    void unknownSessionIsDistinguishedFromStaleSession() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{7}, new byte[]{8});
        long sid = w.establish();
        w.a.send(sid, "x".getBytes());
        byte[] validFrame = w.abLog.get(w.abLog.size() - 1);
        w.a.close(sid);

        // Unknown session id (never existed).
        Packet forged = new Packet(PacketType.DATA, 424242L, 0, 0, new byte[16]);
        w.replayToB(PacketCodec.encode(forged));
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.UNKNOWN_SESSION, 0L));
        // Stale session id (existed, now closed).
        w.replayToB(validFrame);
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.STALE_SESSION, 0L));
    }
}
