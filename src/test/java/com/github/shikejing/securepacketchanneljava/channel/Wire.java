package com.github.shikejing.securepacketchanneljava.channel;

import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;

/**
 * In-memory pipe between two endpoints. Delivery is synchronous. Tests can
 * install transforms to tamper with frames, drop them, or capture them for
 * later replay - all without any external service.
 */
final class Wire {

    final SecureChannelEndpoint a;
    final SecureChannelEndpoint b;

    /** Transform applied to frames travelling a -> b; return null to drop. */
    UnaryOperator<byte[]> abTransform = UnaryOperator.identity();
    /** Transform applied to frames travelling b -> a; return null to drop. */
    UnaryOperator<byte[]> baTransform = UnaryOperator.identity();

    final List<byte[]> abLog = new ArrayList<>();
    final List<byte[]> baLog = new ArrayList<>();

    Wire(SecureChannelEndpoint a, SecureChannelEndpoint b) {
        this.a = a;
        this.b = b;
    }

    static Wire pair(ChannelConfig config, MutableClock clock, byte[] seedA, byte[] seedB) {
        SecureChannelEndpoint a = new SecureChannelEndpoint(config, new DeterministicRandom(seedA), clock);
        SecureChannelEndpoint b = new SecureChannelEndpoint(config, new DeterministicRandom(seedB), clock);
        Wire w = new Wire(a, b);
        w.connect();
        return w;
    }

    void connect() {
        a.setSink(frame -> {
            abLog.add(frame.clone());
            byte[] f = abTransform.apply(frame);
            if (f != null) {
                b.onBytes(f);
            }
        });
        b.setSink(frame -> {
            baLog.add(frame.clone());
            byte[] f = baTransform.apply(frame);
            if (f != null) {
                a.onBytes(f);
            }
        });
    }

    /** Establishes a client handshake from a to b and returns the session id. */
    long establish() {
        HandshakeHandle h = a.connect();
        if (!h.isDone() || h.sessionId().isEmpty()) {
            throw new IllegalStateException("handshake did not complete: " + h.failure());
        }
        return h.sessionId().getAsLong();
    }

    /** Deliver a previously captured frame to endpoint b as-is (replay). */
    void replayToB(byte[] frame) {
        b.onBytes(frame);
    }

    void replayToA(byte[] frame) {
        a.onBytes(frame);
    }
}
