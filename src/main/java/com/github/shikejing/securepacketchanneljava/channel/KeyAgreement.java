package com.github.shikejing.securepacketchanneljava.channel;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;

/**
 * X25519 ECDH + HKDF-SHA256 key negotiation and derivation. All functions
 * are static and deterministic given the same inputs and random source.
 * Failures are reported as {@link HandshakeException} with a classified
 * reason; key material is never included in any error output.
 */
public final class KeyAgreement {

    public static final int PUBLIC_KEY_LEN = 32;
    public static final int RANDOM_LEN = 16;
    public static final int KEY_LEN = 32;
    public static final byte VERSION = 1;

    private KeyAgreement() {
    }

    public static KeyPair generateKeyPair(SecureRandom random) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519");
            gen.initialize(new java.security.spec.NamedParameterSpec("X25519"), random);
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("X25519 not available", e);
        }
    }

    /** 32-byte little-endian u-coordinate encoding. */
    public static byte[] publicKeyBytes(PublicKey key) {
        java.security.interfaces.XECPublicKey xec = (java.security.interfaces.XECPublicKey) key;
        return encodeU(xec.getU());
    }

    public static PublicKey publicKeyFromBytes(byte[] encoded) throws HandshakeException {
        if (encoded == null || encoded.length != PUBLIC_KEY_LEN) {
            throw new HandshakeException(HandshakeFailure.PEER_KEY_INVALID);
        }
        try {
            BigInteger u = decodeU(encoded);
            XECPublicKeySpec spec = new XECPublicKeySpec(NamedParameterSpec.X25519, u);
            return java.security.KeyFactory.getInstance("X25519").generatePublic(spec);
        } catch (Exception e) {
            throw new HandshakeException(HandshakeFailure.PEER_KEY_INVALID);
        }
    }

    /** Raw X25519 shared secret; rejects low-order peer keys. */
    public static byte[] agree(KeyPair own, PublicKey peer) throws HandshakeException {
        try {
            javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("X25519");
            ka.init(own.getPrivate());
            ka.doPhase(peer, true);
            byte[] shared = ka.generateSecret();
            if (isAllZero(shared)) {
                // Low-order public key: refuse to derive keys from it.
                throw new HandshakeException(HandshakeFailure.PEER_KEY_INVALID);
            }
            return shared;
        } catch (HandshakeException e) {
            throw e;
        } catch (Exception e) {
            throw new HandshakeException(HandshakeFailure.PEER_KEY_INVALID);
        }
    }

    /** HKDF-SHA256 (RFC 5869) extract+expand. */
    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            byte[] realSalt = (salt == null) ? new byte[32] : salt;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(realSalt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);

            byte[] out = new byte[length];
            byte[] t = new byte[0];
            int pos = 0;
            int counter = 1;
            while (pos < length) {
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(t);
                mac.update(info);
                mac.update((byte) counter);
                t = mac.doFinal();
                int n = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, out, pos, n);
                pos += n;
                counter++;
            }
            return out;
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 not available", e);
        }
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /** Root of the per-session key chain, bound to the full handshake transcript. */
    public static byte[] deriveChainKey(byte[] sharedSecret, byte[] transcriptHash) {
        return hkdf(sharedSecret, transcriptHash, "spc/chain".getBytes(java.nio.charset.StandardCharsets.UTF_8), KEY_LEN);
    }

    public static long deriveSessionId(byte[] sharedSecret, byte[] transcriptHash) {
        byte[] id = hkdf(sharedSecret, transcriptHash, "spc/session-id".getBytes(java.nio.charset.StandardCharsets.UTF_8), 8);
        long v = 0;
        for (byte b : id) {
            v = (v << 8) | (b & 0xFF);
        }
        return v;
    }

    /** Key-confirmation MAC over the transcript; detects tampering during negotiation. */
    public static byte[] confirmationMac(byte[] sharedSecret, byte[] transcriptHash, byte[] label) {
        byte[] info = new byte["spc/confirm/".length() + label.length];
        System.arraycopy("spc/confirm/".getBytes(java.nio.charset.StandardCharsets.UTF_8), 0, info, 0, "spc/confirm/".length());
        System.arraycopy(label, 0, info, "spc/confirm/".length(), label.length);
        return hkdf(sharedSecret, transcriptHash, info, KEY_LEN);
    }

    /** Advance the chain key on rotation; old chain key must be discarded by the caller. */
    public static byte[] advanceChainKey(byte[] chainKey, int newEpoch) {
        byte[] info = ("spc/rotation/" + newEpoch).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return hkdf(chainKey, null, info, KEY_LEN);
    }

    /** Derive traffic keys for one epoch from the chain key. */
    public static SessionKeys deriveSessionKeys(byte[] chainKey, int epoch, Role role) {
        byte[] c2s = hkdf(chainKey, null, ("spc/epoch/" + epoch + "/c2s").getBytes(java.nio.charset.StandardCharsets.UTF_8), KEY_LEN);
        byte[] s2c = hkdf(chainKey, null, ("spc/epoch/" + epoch + "/s2c").getBytes(java.nio.charset.StandardCharsets.UTF_8), KEY_LEN);
        if (role == Role.CLIENT) {
            return new SessionKeys(epoch, c2s, s2c);
        }
        return new SessionKeys(epoch, s2c, c2s);
    }

    private static byte[] encodeU(BigInteger u) {
        byte[] le = new byte[PUBLIC_KEY_LEN];
        byte[] be = u.toByteArray();
        for (int i = 0; i < PUBLIC_KEY_LEN; i++) {
            int src = be.length - 1 - i;
            le[i] = (src >= 0) ? be[src] : 0;
        }
        return le;
    }

    private static BigInteger decodeU(byte[] le) {
        byte[] be = new byte[le.length + 1];
        for (int i = 0; i < le.length; i++) {
            be[be.length - 1 - i] = le[i];
        }
        return new BigInteger(be);
    }

    private static boolean isAllZero(byte[] b) {
        byte acc = 0;
        for (byte x : b) {
            acc |= x;
        }
        return acc == 0;
    }

    static void erase(byte[] b) {
        if (b != null) {
            Arrays.fill(b, (byte) 0);
        }
    }
}
