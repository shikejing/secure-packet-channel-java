package com.github.shikejing.securepacketchanneljava.channel;

import java.util.BitSet;

/**
 * Sliding replay window over a monotonically increasing sequence space.
 * All decisions are deterministic: a sequence number is either accepted,
 * flagged as a duplicate, or flagged as too old, and a number that fell
 * behind the window is never accepted again.
 */
public final class ReplayWindow {

    public enum Verdict {
        ACCEPTED,
        DUPLICATE,
        TOO_OLD
    }

    private final int size;
    private long highest = -1;
    private final BitSet seen = new BitSet();

    public ReplayWindow(int size) {
        if (size <= 0) {
            throw new IllegalArgumentException("window size must be positive, got " + size);
        }
        this.size = size;
    }

    /** Non-mutating check: the verdict checkAndMark would return for seq. */
    public synchronized Verdict peek(long seq) {
        if (seq < 0) {
            return Verdict.TOO_OLD;
        }
        if (highest < 0 || seq > highest) {
            return Verdict.ACCEPTED;
        }
        long diff = highest - seq;
        if (diff >= size) {
            return Verdict.TOO_OLD;
        }
        return seen.get((int) diff) ? Verdict.DUPLICATE : Verdict.ACCEPTED;
    }

    /** Check-and-mark: records the sequence number iff the verdict is ACCEPTED. */
    public synchronized Verdict checkAndMark(long seq) {
        if (seq < 0) {
            return Verdict.TOO_OLD;
        }
        if (highest < 0) {
            highest = seq;
            seen.set(0);
            return Verdict.ACCEPTED;
        }
        if (seq > highest) {
            long shift = seq - highest;
            if (shift >= size) {
                seen.clear();
                seen.set(0);
            } else {
                shiftLeft((int) shift);
                seen.set(0);
            }
            highest = seq;
            return Verdict.ACCEPTED;
        }
        long diff = highest - seq;
        if (diff >= size) {
            return Verdict.TOO_OLD;
        }
        int idx = (int) diff;
        if (seen.get(idx)) {
            return Verdict.DUPLICATE;
        }
        seen.set(idx);
        return Verdict.ACCEPTED;
    }

    /** Bit i tracks (highest - i); moving the window right shifts bits left. */
    private void shiftLeft(int shift) {
        for (int i = seen.length() - 1; i >= 0; i--) {
            if (seen.get(i)) {
                seen.set(i + shift);
                seen.clear(i);
            }
        }
    }

    public synchronized long highest() {
        return highest;
    }
}
