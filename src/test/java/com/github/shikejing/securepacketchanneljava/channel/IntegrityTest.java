package com.github.shikejing.securepacketchanneljava.channel;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IntegrityTest {

    private static final ChannelConfig CONFIG = ChannelConfig.defaults();

    @Test
    void tamperedCiphertextIsRejectedAndNotDelivered() {
        MutableClock clock = new MutableClock(0);
        ChannelConfig cfg = ChannelConfig.builder().replayWindowSize(4).build();
        Wire w = Wire.pair(cfg, clock, new byte[]{1}, new byte[]{2});
        long sid = w.establish();
        boolean[] tamper = {true};
        w.abTransform = frame -> {
            if (tamper[0] && (frame[0] & 0xFF) == PacketType.DATA.code()) {
                byte[] f = frame.clone();
                f[f.length - 1] ^= 0x40; // flip a bit in the GCM tag
                return f;
            }
            return frame;
        };
        w.a.send(sid, "attack at dawn".getBytes());
        // Tampered packet must not reach the upper layer.
        assertNull(w.b.poll(sid));
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.INTEGRITY_FAILURE, 0L));
        assertEquals(0L, w.b.stats().accepted());

        // Channel still works afterwards: once the replay window slides past
        // the lost sequence number, later messages are delivered in order.
        tamper[0] = false;
        for (int i = 1; i <= 4; i++) {
            w.a.send(sid, ("m" + i).getBytes());
        }
        for (int i = 1; i <= 4; i++) {
            assertArrayEquals(("m" + i).getBytes(), w.b.poll(sid));
        }
        assertNull(w.b.poll(sid));
    }

    @Test
    void tamperedHeaderIsCaughtByAad() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{3}, new byte[]{4});
        long sid = w.establish();
        w.abTransform = frame -> {
            if ((frame[0] & 0xFF) == PacketType.DATA.code()) {
                byte[] f = frame.clone();
                f[13] ^= 0x01; // lowest byte of seq: changes AAD
                return f;
            }
            return frame;
        };
        w.a.send(sid, "hello".getBytes());
        assertNull(w.b.poll(sid));
        assertEquals(1L, w.b.stats().rejectedSnapshot()
                .getOrDefault(RejectReason.INTEGRITY_FAILURE, 0L));
    }

    @Test
    void garbageFramesAreMalformed() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{5}, new byte[]{6});
        long sid = w.establish();
        w.replayToB(new byte[]{1, 2, 3});                 // too short
        w.replayToB(new byte[Packet.HEADER_LEN + 4]);     // unknown type 0x00? type 0 is DATA but zeroed header -> unknown session
        w.replayToB(new byte[]{(byte) 0x7F, 0, 0, 0});    // unknown type
        assertTrue(w.b.stats().rejectedSnapshot().getOrDefault(RejectReason.MALFORMED_PACKET, 0L) >= 2);
        // Session unaffected.
        w.a.send(sid, "still alive".getBytes());
        assertArrayEquals("still alive".getBytes(), w.b.poll(sid));
    }

    @Test
    void ciphertextIsNotPlaintext() {
        MutableClock clock = new MutableClock(0);
        Wire w = Wire.pair(CONFIG, clock, new byte[]{7}, new byte[]{8});
        long sid = w.establish();
        byte[] secret = "top-secret-payload".getBytes();
        w.a.send(sid, secret);
        byte[] frame = w.abLog.get(w.abLog.size() - 1);
        String frameStr = new String(frame, java.nio.charset.StandardCharsets.ISO_8859_1);
        assertFalse(frameStr.contains("top-secret-payload"));
        assertArrayEquals(secret, w.b.poll(sid));
    }
}
