package com.github.shikejing.securepacketchanneljava.channel;

import java.util.Objects;

/**
 * Immutable channel configuration. A new config only affects packets
 * processed after it is installed; in-flight work keeps the old values.
 */
public final class ChannelConfig {

    public static final int DEFAULT_REPLAY_WINDOW_SIZE = 1024;
    public static final int DEFAULT_MAX_IN_FLIGHT = 256;
    public static final long DEFAULT_TIMEOUT_MILLIS = 2_000L;
    public static final int DEFAULT_MAX_RETRIES = 3;

    private final int replayWindowSize;
    private final int maxInFlight;
    private final long timeoutMillis;
    private final int maxRetries;

    private ChannelConfig(Builder b) {
        this.replayWindowSize = b.replayWindowSize;
        this.maxInFlight = b.maxInFlight;
        this.timeoutMillis = b.timeoutMillis;
        this.maxRetries = b.maxRetries;
    }

    public static ChannelConfig defaults() {
        return new Builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public int replayWindowSize() {
        return replayWindowSize;
    }

    public int maxInFlight() {
        return maxInFlight;
    }

    public long timeoutMillis() {
        return timeoutMillis;
    }

    public int maxRetries() {
        return maxRetries;
    }

    public static final class Builder {
        private int replayWindowSize = DEFAULT_REPLAY_WINDOW_SIZE;
        private int maxInFlight = DEFAULT_MAX_IN_FLIGHT;
        private long timeoutMillis = DEFAULT_TIMEOUT_MILLIS;
        private int maxRetries = DEFAULT_MAX_RETRIES;

        public Builder replayWindowSize(int v) {
            this.replayWindowSize = v;
            return this;
        }

        public Builder maxInFlight(int v) {
            this.maxInFlight = v;
            return this;
        }

        public Builder timeoutMillis(long v) {
            this.timeoutMillis = v;
            return this;
        }

        public Builder maxRetries(int v) {
            this.maxRetries = v;
            return this;
        }

        public ChannelConfig build() {
            if (replayWindowSize <= 0 || maxInFlight <= 0) {
                throw new IllegalArgumentException("window sizes must be positive");
            }
            if (timeoutMillis <= 0 || maxRetries < 0) {
                throw new IllegalArgumentException("invalid timeout/retry settings");
            }
            return new ChannelConfig(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ChannelConfig other)) {
            return false;
        }
        return replayWindowSize == other.replayWindowSize
                && maxInFlight == other.maxInFlight
                && timeoutMillis == other.timeoutMillis
                && maxRetries == other.maxRetries;
    }

    @Override
    public int hashCode() {
        return Objects.hash(replayWindowSize, maxInFlight, timeoutMillis, maxRetries);
    }
}
