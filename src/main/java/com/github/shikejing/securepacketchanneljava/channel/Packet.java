package com.github.shikejing.securepacketchanneljava.channel;

import java.util.Arrays;

/**
 * 一条线上报文的结构化表示。密钥代与序号在头部明文可见（路由与重放判定所需），
 * 负载密文与标签不外泄明文内容。
 */
public final class Packet {
    private final int keyEpoch;
    private final long sequence;
    private final byte[] nonce;
    private final byte[] ciphertext;
    private final byte[] tag;

    public Packet(int keyEpoch, long sequence, byte[] nonce, byte[] ciphertext, byte[] tag) {
        this.keyEpoch = keyEpoch;
        this.sequence = sequence;
        this.nonce = Arrays.copyOf(nonce, nonce.length);
        this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
        this.tag = Arrays.copyOf(tag, tag.length);
    }

    public int keyEpoch() { return keyEpoch; }
    public long sequence() { return sequence; }
    public byte[] nonce() { return Arrays.copyOf(nonce, nonce.length); }
    public byte[] ciphertext() { return Arrays.copyOf(ciphertext, ciphertext.length); }
    public byte[] tag() { return Arrays.copyOf(tag, tag.length); }
}
