package com.github.shikejing.securepacketchanneljava.channel;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 每个会话的可观测接受/拒绝统计。线程安全；快照为不可变副本。
 */
public final class ChannelStats {
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong rotations = new AtomicLong();
    private final AtomicLong rotationRollbacks = new AtomicLong();
    private final EnumMap<RejectReason, AtomicLong> rejects = new EnumMap<>(RejectReason.class);

    public ChannelStats() {
        for (RejectReason r : RejectReason.values()) {
            rejects.put(r, new AtomicLong());
        }
    }

    public void recordSent() { sent.incrementAndGet(); }
    public void recordAccepted() { accepted.incrementAndGet(); }
    public void recordRotation() { rotations.incrementAndGet(); }
    public void recordRotationRollback() { rotationRollbacks.incrementAndGet(); }
    public void recordReject(RejectReason reason) { rejects.get(reason).incrementAndGet(); }

    public Snapshot snapshot() {
        EnumMap<RejectReason, Long> r = new EnumMap<>(RejectReason.class);
        for (Map.Entry<RejectReason, AtomicLong> e : rejects.entrySet()) {
            r.put(e.getKey(), e.getValue().get());
        }
        return new Snapshot(sent.get(), accepted.get(), rotations.get(), rotationRollbacks.get(), r);
    }

    /** 不可变统计快照。 */
    public static final class Snapshot {
        private final long sent;
        private final long accepted;
        private final long rotations;
        private final long rotationRollbacks;
        private final EnumMap<RejectReason, Long> rejects;

        Snapshot(long sent, long accepted, long rotations, long rotationRollbacks, EnumMap<RejectReason, Long> rejects) {
            this.sent = sent;
            this.accepted = accepted;
            this.rotations = rotations;
            this.rotationRollbacks = rotationRollbacks;
            this.rejects = rejects;
        }

        public long sent() { return sent; }
        public long accepted() { return accepted; }
        public long rotations() { return rotations; }
        public long rotationRollbacks() { return rotationRollbacks; }
        public long rejected(RejectReason reason) { return rejects.get(reason); }
        public long totalRejected() {
            long sum = 0;
            for (long v : rejects.values()) sum += v;
            return sum;
        }

        @Override
        public String toString() {
            return "Snapshot{sent=" + sent + ", accepted=" + accepted
                    + ", rotations=" + rotations + ", rotationRollbacks=" + rotationRollbacks
                    + ", rejects=" + rejects + '}';
        }
    }
}
