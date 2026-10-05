package com.github.shikejing.securepacketchanneljava.channel;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * Symmetric traffic keys for one key epoch of one session. Package-private:
 * key material must never leak into logs, errors or any observable output.
 */
final class SessionKeys {

    private final int epoch;
    private final SecretKey sendKey;
    private final SecretKey recvKey;

    SessionKeys(int epoch, byte[] sendKeyBytes, byte[] recvKeyBytes) {
        this.epoch = epoch;
        this.sendKey = new SecretKeySpec(sendKeyBytes, "AES");
        this.recvKey = new SecretKeySpec(recvKeyBytes, "AES");
    }

    int epoch() {
        return epoch;
    }

    SecretKey sendKey() {
        return sendKey;
    }

    SecretKey recvKey() {
        return recvKey;
    }

    /** Best-effort erasure of key material. */
    void destroy() {
        try {
            sendKey.destroy();
            recvKey.destroy();
        } catch (Exception ignored) {
            // SecretKeySpec.destroy() is a no-op on some providers; ignore.
        }
    }

    @Override
    public String toString() {
        // Never print key material.
        return "SessionKeys{epoch=" + epoch + "}";
    }
}
