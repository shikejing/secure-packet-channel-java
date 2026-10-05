package com.github.shikejing.securepacketchanneljava.channel;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;

/**
 * 控制报文负载编解码。控制报文本身走 PacketCodec 的 CONTROL 类型槽位。
 * 所有字段都不含密钥材料，只有临时公钥与序号状态。
 */
public final class ControlCodec {
    public static final byte HELLO = 1;
    public static final byte HELLO_ACK = 2;
    public static final byte RESUME = 3;
    public static final byte RESUME_ACK = 4;
    public static final byte RESUME_REJECT = 5;
    public static final byte ROTATE = 6;
    public static final byte ROTATE_COMMIT = 7;
    public static final byte ROTATE_ABORT = 8;

    private ControlCodec() {}

    public record Hello(byte kind, long sessionId, int generation, long lastSent, long lastRecv, byte[] publicKey) {}

    public record Rotate(byte kind, int newEpoch, long nonce) {}

    public static byte[] encodeHello(byte kind, long sessionId, int generation, long lastSent, long lastRecv, byte[] publicKey) {
        ByteBuffer buf = ByteBuffer.allocate(1 + 8 + 4 + 8 + 8 + 2 + publicKey.length);
        buf.put(kind).putLong(sessionId).putInt(generation).putLong(lastSent).putLong(lastRecv);
        buf.putShort((short) publicKey.length).put(publicKey);
        return buf.array();
    }

    public static Optional<Hello> decodeHello(byte[] payload) {
        if (payload == null || payload.length < 1 + 8 + 4 + 8 + 8 + 2) return Optional.empty();
        try {
            ByteBuffer buf = ByteBuffer.wrap(payload);
            byte kind = buf.get();
            long sessionId = buf.getLong();
            int generation = buf.getInt();
            long lastSent = buf.getLong();
            long lastRecv = buf.getLong();
            int pubLen = Short.toUnsignedInt(buf.getShort());
            if (pubLen != buf.remaining()) return Optional.empty();
            byte[] pub = new byte[pubLen];
            buf.get(pub);
            return Optional.of(new Hello(kind, sessionId, generation, lastSent, lastRecv, pub));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    public static byte[] encodeResumeReject(HandshakeFailure failure) {
        return new byte[]{RESUME_REJECT, (byte) failure.ordinal()};
    }

    public static Optional<HandshakeFailure> decodeResumeReject(byte[] payload) {
        if (payload == null || payload.length != 2 || payload[0] != RESUME_REJECT) return Optional.empty();
        int ord = payload[1] & 0xFF;
        HandshakeFailure[] values = HandshakeFailure.values();
        if (ord >= values.length) return Optional.empty();
        return Optional.of(values[ord]);
    }

    public static byte[] encodeRotate(byte kind, int newEpoch, long nonce) {
        ByteBuffer buf = ByteBuffer.allocate(1 + 4 + 8);
        buf.put(kind).putInt(newEpoch).putLong(nonce);
        return buf.array();
    }

    public static Optional<Rotate> decodeRotate(byte[] payload) {
        if (payload == null || payload.length != 1 + 4 + 8) return Optional.empty();
        ByteBuffer buf = ByteBuffer.wrap(payload);
        byte kind = buf.get();
        int newEpoch = buf.getInt();
        long nonce = buf.getLong();
        return Optional.of(new Rotate(kind, newEpoch, nonce));
    }

    /** 深拷贝防御：Hello 公钥不可变访问。 */
    public static byte[] copyPublicKey(Hello h) {
        return Arrays.copyOf(h.publicKey(), h.publicKey().length);
    }
}
