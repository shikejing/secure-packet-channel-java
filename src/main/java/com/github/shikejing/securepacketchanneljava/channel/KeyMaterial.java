package com.github.shikejing.securepacketchanneljava.channel;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 单向会话密钥材料（加密密钥 + 显式 nonce 前缀）。
 * 不可变；toString 不输出任何密钥字节，密钥材料不会出现在日志与错误信息中。
 */
public final class KeyMaterial {
    private final byte[] encKey;
    private final byte[] noncePrefix;

    public KeyMaterial(byte[] encKey, byte[] noncePrefix) {
        this.encKey = Arrays.copyOf(encKey, encKey.length);
        this.noncePrefix = Arrays.copyOf(noncePrefix, noncePrefix.length);
    }

    public byte[] encKey() {
        return Arrays.copyOf(encKey, encKey.length);
    }

    public byte[] noncePrefix() {
        return Arrays.copyOf(noncePrefix, noncePrefix.length);
    }

    public static byte[] randomBytes(SecureRandom random, int len) {
        byte[] b = new byte[len];
        random.nextBytes(b);
        return b;
    }

    @Override
    public String toString() {
        return "KeyMaterial[redacted]";
    }
}
