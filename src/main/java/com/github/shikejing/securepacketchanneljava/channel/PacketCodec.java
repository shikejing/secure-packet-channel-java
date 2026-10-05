package com.github.shikejing.securepacketchanneljava.channel;

import java.util.Arrays;

/**
 * Stateless wire-format encoder/decoder. Header layout:
 * type(1) | sessionId(8) | epoch(4) | seq(8) | payload...
 * The header bytes are used as AEAD associated data by the session layer.
 */
public final class PacketCodec {

    private PacketCodec() {
    }

    public static byte[] encode(Packet packet) {
        byte[] out = new byte[Packet.HEADER_LEN + packet.payload().length];
        out[0] = (byte) packet.type().code();
        writeLong(out, 1, packet.sessionId());
        writeInt(out, 9, packet.epoch());
        writeLong(out, 13, packet.seq());
        System.arraycopy(packet.payload(), 0, out, Packet.HEADER_LEN, packet.payload().length);
        return out;
    }

    /** @return decoded packet, or null when the frame is malformed. */
    public static Packet decode(byte[] frame) {
        if (frame == null || frame.length < Packet.HEADER_LEN) {
            return null;
        }
        PacketType type = PacketType.fromCode(frame[0] & 0xFF);
        if (type == null) {
            return null;
        }
        long sessionId = readLong(frame, 1);
        int epoch = readInt(frame, 9);
        long seq = readLong(frame, 13);
        byte[] payload = Arrays.copyOfRange(frame, Packet.HEADER_LEN, frame.length);
        return new Packet(type, sessionId, epoch, seq, payload);
    }

    /** Header bytes of an encoded frame, for use as AEAD associated data. */
    public static byte[] headerOf(byte[] frame) {
        if (frame == null || frame.length < Packet.HEADER_LEN) {
            return new byte[0];
        }
        return Arrays.copyOf(frame, Packet.HEADER_LEN);
    }

    private static void writeLong(byte[] out, int off, long v) {
        for (int i = 7; i >= 0; i--) {
            out[off + i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
    }

    private static void writeInt(byte[] out, int off, int v) {
        for (int i = 3; i >= 0; i--) {
            out[off + i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
    }

    private static long readLong(byte[] in, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (in[off + i] & 0xFF);
        }
        return v;
    }

    private static int readInt(byte[] in, int off) {
        int v = 0;
        for (int i = 0; i < 4; i++) {
            v = (v << 8) | (in[off + i] & 0xFF);
        }
        return v;
    }
}
