package com.github.shikejing.securepacketchanneljava.channel;

import java.util.Objects;

/**
 * 通道可配置项。配置为不可变对象；变更只影响后续报文，
 * 通过 {@link SecureSession#updateConfig} 原子替换，进行中的接收逻辑不会读到半更新状态。
 */
public final class ChannelConfig {
    public static final int MAX_WINDOW_SIZE = 1024;

    private final int replayWindowSize;
    private final int maxInFlight;
    private final long handshakeTimeoutMillis;
    private final int maxHandshakeRetries;
    private final long rotationIntervalMillis;

    private ChannelConfig(Builder b) {
        this.replayWindowSize = b.replayWindowSize;
        this.maxInFlight = b.maxInFlight;
        this.handshakeTimeoutMillis = b.handshakeTimeoutMillis;
        this.maxHandshakeRetries = b.maxHandshakeRetries;
        this.rotationIntervalMillis = b.rotationIntervalMillis;
    }

    public static ChannelConfig defaults() {
        return new Builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public int replayWindowSize() { return replayWindowSize; }
    public int maxInFlight() { return maxInFlight; }
    public long handshakeTimeoutMillis() { return handshakeTimeoutMillis; }
    public int maxHandshakeRetries() { return maxHandshakeRetries; }
    public long rotationIntervalMillis() { return rotationIntervalMillis; }

    public static final class Builder {
        private int replayWindowSize = 64;
        private int maxInFlight = 256;
        private long handshakeTimeoutMillis = 5_000;
        private int maxHandshakeRetries = 3;
        private long rotationIntervalMillis = 60_000;

        public Builder replayWindowSize(int v) {
            if (v < 1 || v > MAX_WINDOW_SIZE) throw new IllegalArgumentException("replayWindowSize out of range: " + v);
            this.replayWindowSize = v; return this;
        }
        public Builder maxInFlight(int v) {
            if (v < 1) throw new IllegalArgumentException("maxInFlight must be >= 1");
            this.maxInFlight = v; return this;
        }
        public Builder handshakeTimeoutMillis(long v) {
            if (v < 1) throw new IllegalArgumentException("handshakeTimeoutMillis must be >= 1");
            this.handshakeTimeoutMillis = v; return this;
        }
        public Builder maxHandshakeRetries(int v) {
            if (v < 0) throw new IllegalArgumentException("maxHandshakeRetries must be >= 0");
            this.maxHandshakeRetries = v; return this;
        }
        public Builder rotationIntervalMillis(long v) {
            if (v < 1) throw new IllegalArgumentException("rotationIntervalMillis must be >= 1");
            this.rotationIntervalMillis = v; return this;
        }
        public ChannelConfig build() {
            return new ChannelConfig(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ChannelConfig c)) return false;
        return replayWindowSize == c.replayWindowSize && maxInFlight == c.maxInFlight
                && handshakeTimeoutMillis == c.handshakeTimeoutMillis
                && maxHandshakeRetries == c.maxHandshakeRetries
                && rotationIntervalMillis == c.rotationIntervalMillis;
    }

    @Override
    public int hashCode() {
        return Objects.hash(replayWindowSize, maxInFlight, handshakeTimeoutMillis, maxHandshakeRetries, rotationIntervalMillis);
    }
}
