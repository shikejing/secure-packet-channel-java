package com.github.shikejing.securepacketchanneljava.channel;

import java.util.function.LongSupplier;

/** Manually advanced clock for deterministic timeout/retry tests. */
final class MutableClock implements LongSupplier {

    private long now;

    MutableClock(long start) {
        this.now = start;
    }

    @Override
    public long getAsLong() {
        return now;
    }

    void advance(long millis) {
        now += millis;
    }
}
