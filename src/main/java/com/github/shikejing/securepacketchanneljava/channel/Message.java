package com.github.shikejing.securepacketchanneljava.channel;

import java.util.Arrays;

/**
 * 一条通过完整性校验并交付给上层的报文。
 */
public final class Message {
    private final long sequence;
    private final int keyEpoch;
    private final byte[] payload;

    public Message(long sequence, int keyEpoch, byte[] payload) {
        this.sequence = sequence;
        this.keyEpoch = keyEpoch;
        this.payload = Arrays.copyOf(payload, payload.length);
    }

    public long sequence() { return sequence; }
    public int keyEpoch() { return keyEpoch; }
    public byte[] payload() { return Arrays.copyOf(payload, payload.length); }

    @Override
    public String toString() {
        return "Message{seq=" + sequence + ", epoch=" + keyEpoch + ", bytes=" + payload.length + '}';
    }
}
