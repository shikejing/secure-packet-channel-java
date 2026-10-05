package com.github.shikejing.securepacketchanneljava.channel;

/**
 * Thrown when key negotiation fails. Carries only a classified reason and
 * the session id (if known); key material never appears in the message.
 */
public class HandshakeException extends Exception {

    private final HandshakeFailure failure;

    public HandshakeException(HandshakeFailure failure) {
        super("handshake failed: " + failure);
        this.failure = failure;
    }

    public HandshakeFailure failure() {
        return failure;
    }
}
