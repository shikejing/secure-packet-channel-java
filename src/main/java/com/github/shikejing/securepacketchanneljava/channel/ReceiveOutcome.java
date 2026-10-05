package com.github.shikejing.securepacketchanneljava.channel;

/**
 * Result of feeding one packet into a session: either accepted (and, for
 * DATA, queued for in-order delivery) or rejected with a classified reason.
 */
public final class ReceiveOutcome {

    private static final ReceiveOutcome ACCEPTED = new ReceiveOutcome(true, null);

    private final boolean accepted;
    private final RejectReason reason;

    private ReceiveOutcome(boolean accepted, RejectReason reason) {
        this.accepted = accepted;
        this.reason = reason;
    }

    public static ReceiveOutcome accepted() {
        return ACCEPTED;
    }

    public static ReceiveOutcome rejected(RejectReason reason) {
        return new ReceiveOutcome(false, reason);
    }

    public boolean isAccepted() {
        return accepted;
    }

    /** Non-null iff rejected. */
    public RejectReason reason() {
        return reason;
    }
}
