package com.github.shikejing.securepacketchanneljava.channel;

import java.util.OptionalLong;

/**
 * Observable handle for an in-flight client handshake. With a synchronous
 * in-memory wire the handshake usually completes before connect() returns;
 * with drops, tick() drives retries until success or a classified failure.
 */
public final class HandshakeHandle {

    private volatile long sessionId;
    private volatile boolean hasSessionId;
    private volatile HandshakeFailure failure;
    private volatile boolean done;

    HandshakeHandle() {
    }

    /** Session id once the handshake completed; empty while pending/failed. */
    public OptionalLong sessionId() {
        return hasSessionId ? OptionalLong.of(sessionId) : OptionalLong.empty();
    }

    /** Null while pending; the classified failure once the handshake failed. */
    public HandshakeFailure failure() {
        return failure;
    }

    public boolean isDone() {
        return done;
    }

    void complete(long id) {
        this.sessionId = id;
        this.hasSessionId = true;
        this.done = true;
    }

    void fail(HandshakeFailure f) {
        this.failure = f;
        this.done = true;
    }
}
