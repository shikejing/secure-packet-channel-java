package com.github.shikejing.securepacketchanneljava.channel;

/**
 * Reasons a key negotiation can fail. Kept strictly separate from
 * {@link RejectReason} so callers can tell negotiation problems apart
 * from message-integrity problems.
 */
public enum HandshakeFailure {
    /** Peer public key is malformed or not on the expected curve. */
    PEER_KEY_INVALID,
    /** Protocol version offered by the peer is not supported. */
    VERSION_MISMATCH,
    /** Key-confirmation MAC did not match: the transcript was tampered with. */
    TRANSCRIPT_MISMATCH,
    /** Handshake did not complete within the configured timeout. */
    TIMED_OUT,
    /** Retransmission budget was exhausted before the peer answered. */
    RETRIES_EXHAUSTED,
    /** Handshake message arrived in a state where it is not allowed. */
    ILLEGAL_STATE
}
