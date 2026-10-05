package com.github.shikejing.securepacketchanneljava.channel;

/**
 * Classified reasons why a received packet was rejected.
 * Integrity/verification failures are deliberately kept distinct from
 * handshake failures (see {@link HandshakeFailure}).
 */
public enum RejectReason {
    /** Frame could not be parsed at all. */
    MALFORMED_PACKET,
    /** Session id is not known to this endpoint. */
    UNKNOWN_SESSION,
    /** Session id belongs to a session that was closed/replaced (e.g. after reconnect). */
    STALE_SESSION,
    /** Session exists but handshake has not completed yet. */
    SESSION_NOT_ESTABLISHED,
    /** Session has been closed. */
    SESSION_CLOSED,
    /** AEAD verification failed: the packet was modified on the wire. */
    INTEGRITY_FAILURE,
    /** Sequence number was already consumed (replay). */
    REPLAY_DUPLICATE,
    /** Sequence number fell behind the replay window and will never be accepted again. */
    TOO_OLD,
    /** Packet belongs to a key epoch this endpoint no longer accepts. */
    STALE_EPOCH,
    /** In-order delivery buffer is full; packet cannot be held. */
    BUFFER_OVERFLOW,
    /** Control packet that does not fit the current protocol state. */
    UNEXPECTED_CONTROL
}
