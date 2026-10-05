package com.github.shikejing.securepacketchanneljava.channel;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Observable accept/reject counters. Counters never contain key material.
 */
public final class ChannelStats {

    private final AtomicLong accepted = new AtomicLong();
    private final Map<RejectReason, AtomicLong> rejected = new ConcurrentHashMap<>();
    private final AtomicLong rotationsCommitted = new AtomicLong();
    private final AtomicLong rotationsRolledBack = new AtomicLong();
    private final AtomicLong handshakesCompleted = new AtomicLong();
    private final Map<HandshakeFailure, AtomicLong> handshakesFailed = new ConcurrentHashMap<>();

    public void recordAccepted() {
        accepted.incrementAndGet();
    }

    public void recordRejected(RejectReason reason) {
        rejected.computeIfAbsent(reason, k -> new AtomicLong()).incrementAndGet();
    }

    public void recordRotationCommitted() {
        rotationsCommitted.incrementAndGet();
    }

    public void recordRotationRolledBack() {
        rotationsRolledBack.incrementAndGet();
    }

    public void recordHandshakeCompleted() {
        handshakesCompleted.incrementAndGet();
    }

    public void recordHandshakeFailed(HandshakeFailure failure) {
        handshakesFailed.computeIfAbsent(failure, k -> new AtomicLong()).incrementAndGet();
    }

    public long accepted() {
        return accepted.get();
    }

    public long rotationsCommitted() {
        return rotationsCommitted.get();
    }

    public long rotationsRolledBack() {
        return rotationsRolledBack.get();
    }

    public long handshakesCompleted() {
        return handshakesCompleted.get();
    }

    public Map<RejectReason, Long> rejectedSnapshot() {
        Map<RejectReason, Long> out = new EnumMap<>(RejectReason.class);
        rejected.forEach((k, v) -> out.put(k, v.get()));
        return Collections.unmodifiableMap(out);
    }

    public Map<HandshakeFailure, Long> handshakeFailureSnapshot() {
        Map<HandshakeFailure, Long> out = new EnumMap<>(HandshakeFailure.class);
        handshakesFailed.forEach((k, v) -> out.put(k, v.get()));
        return Collections.unmodifiableMap(out);
    }
}
