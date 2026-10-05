package com.github.shikejing.securepacketchanneljava.channel;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * SHA-256 counter DRBG for reproducible tests: same seed bytes produce the
 * same byte stream, so an entire run (key pairs, nonces, session ids) is
 * replayable from the seed.
 */
public final class DeterministicRandom extends SecureRandom {

    private final byte[] state;
    private long counter;
    private byte[] buffer = new byte[0];
    private int pos;

    public DeterministicRandom(byte[] seed) {
        this.state = seed.clone();
    }

    @Override
    public synchronized void nextBytes(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            if (pos >= buffer.length) {
                refill();
            }
            bytes[i] = buffer[pos++];
        }
    }

    private void refill() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(state);
            for (int i = 0; i < 8; i++) {
                md.update((byte) (counter >>> (i * 8)));
            }
            counter++;
            buffer = md.digest();
            pos = 0;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String toString() {
        return "DeterministicRandom";
    }
}
