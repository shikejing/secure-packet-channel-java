package com.github.shikejing.securepacketchanneljava.channel;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * 加密原语封装：X25519 协商、HKDF-SHA256 派生、AES-CTR + HMAC-SHA256（Encrypt-then-MAC）。
 * 所有失败只返回空或抛出不含密钥材料的通用异常。
 */
public final class CryptoUtil {
    public static final int KEY_LEN = 32;
    public static final int NONCE_PREFIX_LEN = 8;
    public static final int NONCE_LEN = 16;
    public static final int TAG_LEN = 32;

    private CryptoUtil() {}

    // ---------- 随机源 ----------

    /** 由固定种子构造确定性随机源，用于可复现测试。 */
    public static SecureRandom deterministicRandom(long seed) {
        return new SecureRandom() {
            private long state = seed;

            @Override
            public synchronized void nextBytes(byte[] bytes) {
                // SplitMix64 驱动，输出仅依赖种子与调用次序，保证可复现。
                for (int i = 0; i < bytes.length; i += 8) {
                    state += 0x9E3779B97F4A7C15L;
                    long z = state;
                    z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
                    z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
                    z = z ^ (z >>> 31);
                    for (int j = 0; j < 8 && i + j < bytes.length; j++) {
                        bytes[i + j] = (byte) (z >>> (8 * j));
                    }
                }
            }

            @Override
            public String toString() {
                return "DeterministicSecureRandom";
            }
        };
    }

    // ---------- X25519 ----------

    public static KeyPair generateX25519(SecureRandom random) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519");
            gen.initialize(255, random);
            return gen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 unavailable", e);
        }
    }

    public static byte[] encodePublic(PublicKey key) {
        return key.getEncoded();
    }

    public static PublicKey decodePublic(byte[] encoded) throws GeneralSecurityException {
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static byte[] agree(PrivateKey priv, byte[] peerPublicEncoded) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(priv);
        ka.doPhase(decodePublic(peerPublicEncoded), true);
        return ka.generateSecret();
    }

    // ---------- HKDF-SHA256 ----------

    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int outLen) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            byte[] out = new byte[outLen];
            byte[] t = new byte[0];
            int pos = 0;
            for (int i = 1; pos < outLen; i++) {
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(t);
                mac.update(info);
                mac.update((byte) i);
                t = mac.doFinal();
                int n = Math.min(t.length, outLen - pos);
                System.arraycopy(t, 0, out, pos, n);
                pos += n;
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF unavailable", e);
        }
    }

    /** 由 64 字节主密钥块派生双向会话密钥：c2s(32) | s2c(32)。 */
    public static KeyMaterial keyMaterial(byte[] masterBlock, boolean client) {
        byte[] enc = Arrays.copyOfRange(masterBlock, client ? 0 : 32, client ? 32 : 64);
        byte[] prefix = hkdf(enc, new byte[KEY_LEN], "nonce-prefix".getBytes(java.nio.charset.StandardCharsets.UTF_8), NONCE_PREFIX_LEN);
        return new KeyMaterial(enc, prefix);
    }

    // ---------- AEAD（Encrypt-then-MAC） ----------

    /** 认证附加数据：epoch | sequence | nonce | ciphertext。 */
    private static byte[] aad(int epoch, long sequence, byte[] nonce, byte[] ciphertext) {
        byte[] aad = new byte[4 + 8 + nonce.length + ciphertext.length];
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(aad);
        buf.putInt(epoch).putLong(sequence).put(nonce).put(ciphertext);
        return aad;
    }

    public static byte[] nonce(byte[] prefix, long sequence) {
        byte[] nonce = Arrays.copyOf(prefix, NONCE_LEN);
        for (int i = 0; i < 8; i++) {
            nonce[NONCE_PREFIX_LEN + i] = (byte) (sequence >>> (56 - 8 * i));
        }
        return nonce;
    }

    public static byte[] encrypt(byte[] key, byte[] nonce, int epoch, long sequence, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(nonce));
            byte[] ct = cipher.doFinal(plaintext);
            byte[] out = new byte[ct.length + TAG_LEN];
            System.arraycopy(ct, 0, out, 0, ct.length);
            System.arraycopy(tag(key, aad(epoch, sequence, nonce, ct)), 0, out, ct.length, TAG_LEN);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cipher failure", e);
        }
    }

    /** 解密失败（含标签不匹配）返回 null，不泄露任何明文或密钥信息。 */
    public static byte[] decrypt(byte[] key, byte[] nonce, int epoch, long sequence, byte[] ctAndTag) {
        if (ctAndTag == null || ctAndTag.length < TAG_LEN) return null;
        try {
            int ctLen = ctAndTag.length - TAG_LEN;
            byte[] ct = Arrays.copyOf(ctAndTag, ctLen);
            byte[] expected = tag(key, aad(epoch, sequence, nonce, ct));
            if (!MessageDigest.isEqual(expected, Arrays.copyOfRange(ctAndTag, ctLen, ctAndTag.length))) {
                return null;
            }
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(nonce));
            return cipher.doFinal(ct);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    private static byte[] tag(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("mac failure", e);
        }
    }
}
