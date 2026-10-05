package com.github.shikejing.securepacketchanneljava.channel;

/**
 * Decoded wire frame. Payload semantics depend on the type: for DATA and
 * protected control frames it is ciphertext||tag, for HELLO/HELLO2 it is
 * the plaintext handshake body.
 */
public record Packet(PacketType type, long sessionId, int epoch, long seq, byte[] payload) {

    public static final int HEADER_LEN = 1 + 8 + 4 + 8;

    public boolean isControl() {
        return type != PacketType.DATA;
    }
}
