package com.github.shikejing.securepacketchanneljava.channel;

/** Lifecycle of a single secure session. */
public enum SessionState {
    HANDSHAKING,
    ESTABLISHED,
    /** A key rotation has been initiated but not yet confirmed. */
    ROTATING,
    CLOSED
}
