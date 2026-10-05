package com.github.shikejing.securepacketchanneljava.channel;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * 线上字节格式：
 * <pre>
 * magic(2) | version(1) | type(1) | keyEpoch(4) | sequence(8)
 * | nonceLen(2) nonce | ctLen(4) ciphertext | tagLen(2) tag
 * </pre>
 * 控制报文（握手/轮换）type 非 DATA，sequence 恒为 0，nonce/ciphertext/tag 为空。
 */
public final class PacketCodec {
    public static final short MAGIC = (short) 0x5A43;
    public static final byte VERSION = 1;
    public static final byte TYPE_DATA = 0;
    public static final byte TYPE_CONTROL = 1;

    private PacketCodec() {}

    public static byte[] encodeData(Packet p) {
        ByteBuffer buf = ByteBuffer.allocate(HEADER_LEN + 2 + p.nonce().length + 4 + p.ciphertext().length + 2 + p.tag().length);
        putHeader(buf, TYPE_DATA, p.keyEpoch(), p.sequence());
        buf.putShort((short) p.nonce().length).put(p.nonce());
        buf.putInt(p.ciphertext().length).put(p.ciphertext());
        buf.putShort((short) p.tag().length).put(p.tag());
        return buf.array();
    }

    public static byte[] encodeControl(int keyEpoch, byte[] payload) {
        ByteBuffer buf = ByteBuffer.allocate(HEADER_LEN + 2 + 4 + payload.length + 2);
        putHeader(buf, TYPE_CONTROL, keyEpoch, 0L);
        buf.putShort((short) 0);          // nonceLen
        buf.putInt(payload.length).put(payload); // 控制负载放在 ciphertext 槽位
        buf.putShort((short) 0);          // tagLen
        return buf.array();
    }

    private static final int HEADER_LEN = 2 + 1 + 1 + 4 + 8;

    private static void putHeader(ByteBuffer buf, byte type, int keyEpoch, long sequence) {
        buf.putShort(MAGIC).put(VERSION).put(type).putInt(keyEpoch).putLong(sequence);
    }

    /** 解析失败返回 empty，不抛出携带报文内容的异常。 */
    public static Optional<Parsed> decode(byte[] bytes) {
        if (bytes == null || bytes.length < HEADER_LEN + 8) return Optional.empty();
        try {
            ByteBuffer buf = ByteBuffer.wrap(bytes);
            if (buf.getShort() != MAGIC) return Optional.empty();
            if (buf.get() != VERSION) return Optional.empty();
            byte type = buf.get();
            int keyEpoch = buf.getInt();
            long sequence = buf.getLong();
            int nonceLen = Short.toUnsignedInt(buf.getShort());
            if (nonceLen > buf.remaining()) return Optional.empty();
            byte[] nonce = new byte[nonceLen];
            buf.get(nonce);
            if (buf.remaining() < 4) return Optional.empty();
            int ctLen = buf.getInt();
            if (ctLen < 0 || ctLen > buf.remaining()) return Optional.empty();
            byte[] ct = new byte[ctLen];
            buf.get(ct);
            if (buf.remaining() < 2) return Optional.empty();
            int tagLen = Short.toUnsignedInt(buf.getShort());
            if (tagLen != buf.remaining()) return Optional.empty();
            byte[] tag = new byte[tagLen];
            buf.get(tag);
            return Optional.of(new Parsed(type, keyEpoch, sequence, nonce, ct, tag));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    public record Parsed(byte type, int keyEpoch, long sequence, byte[] nonce, byte[] ciphertext, byte[] tag) {
        public boolean isControl() { return type == TYPE_CONTROL; }
        public Packet toDataPacket() { return new Packet(keyEpoch, sequence, nonce, ciphertext, tag); }
    }
}
