package com.github.shikejing.securepacketchanneljava.channel;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/**
 * One end of the secure packet channel. Owns any number of concurrent
 * sessions; each session is isolated behind its own monitor so a broken or
 * hostile session cannot disturb the others. Both ends communicate only
 * through the sink/onBytes pair, which tests wire to an in-memory pipe or
 * a local loopback - no external service is involved.
 *
 * Determinism: pass a seeded SecureRandom and a controllable clock to make
 * the whole endpoint reproducible.
 */
public final class SecureChannelEndpoint {

    private static final int MAX_REMEMBERED_CLOSED_SESSIONS = 1024;

    // HELLO body:  version(1) | clientRandom(16) | clientPub(32)
    // HELLO2 body: clientRandomEcho(16) | serverRandom(16) | serverPub(32) | serverConfirm(32)
    // HELLO2 err:  clientRandomEcho(16) | errorCode(1)
    private static final int HELLO_BODY_LEN = 1 + KeyAgreement.RANDOM_LEN + KeyAgreement.PUBLIC_KEY_LEN;
    private static final int HELLO2_BODY_LEN = KeyAgreement.RANDOM_LEN * 2 + KeyAgreement.PUBLIC_KEY_LEN + KeyAgreement.KEY_LEN;
    private static final byte ERR_VERSION = 1;
    private static final byte ERR_PEER_KEY = 2;

    private final Object handshakeLock = new Object();
    private final Map<String, ClientHandshake> pendingClient = new ConcurrentHashMap<>();
    private final Map<Long, ServerHandshake> pendingServer = new ConcurrentHashMap<>();
    private final Map<Long, SecureSession> sessions = new ConcurrentHashMap<>();
    private final Set<Long> closedSessions = new LinkedHashSet<>();
    private final ChannelStats stats = new ChannelStats();
    private final SecureRandom random;
    private final LongSupplier clock;

    private volatile ChannelConfig config;
    private volatile Consumer<byte[]> sink;

    // Outbound frames are queued inside session critical sections and
    // drained outside any lock, so delivery can be synchronous (and even
    // re-enter this endpoint) without risking deadlock or reordering.
    private final java.util.concurrent.ConcurrentLinkedQueue<byte[]> outbox =
            new java.util.concurrent.ConcurrentLinkedQueue<>();
    private final java.util.concurrent.atomic.AtomicBoolean draining =
            new java.util.concurrent.atomic.AtomicBoolean();

    public SecureChannelEndpoint(ChannelConfig config, SecureRandom random, LongSupplier clock) {
        this.config = config;
        this.random = random;
        this.clock = clock;
    }

    /** Where outgoing frames go. Typically the peer's onBytes, via a pipe. */
    public void setSink(Consumer<byte[]> sink) {
        this.sink = sink;
    }

    // ------------------------------------------------------------------
    // Handshake: client side
    // ------------------------------------------------------------------

    /** Initiate a client handshake. */
    public HandshakeHandle connect() {
        HandshakeHandle handle = new HandshakeHandle();
        byte[] clientRandom = new byte[KeyAgreement.RANDOM_LEN];
        random.nextBytes(clientRandom);
        KeyPair keyPair = KeyAgreement.generateKeyPair(random);
        byte[] helloBody = ByteBuffer.allocate(HELLO_BODY_LEN)
                .put(KeyAgreement.VERSION)
                .put(clientRandom)
                .put(KeyAgreement.publicKeyBytes(keyPair.getPublic()))
                .array();
        ClientHandshake ctx = new ClientHandshake();
        ctx.handle = handle;
        ctx.keyPair = keyPair;
        ctx.clientRandom = clientRandom;
        ctx.helloBody = helloBody;
        ctx.helloFrame = PacketCodec.encode(new Packet(PacketType.HELLO, 0L, 0, 0L, helloBody));
        ctx.retriesLeft = config.maxRetries();
        ctx.deadline = now() + config.timeoutMillis();
        pendingClient.put(hex(clientRandom), ctx);
        emit(ctx.helloFrame);
        return handle;
    }

    private void onHello2(Packet packet) {
        byte[] body = packet.payload();
        if (body.length == KeyAgreement.RANDOM_LEN + 1) {
            // Server-side negotiation failure, echoed back with a reason code.
            byte[] echo = Arrays.copyOf(body, KeyAgreement.RANDOM_LEN);
            ClientHandshake ctx = pendingClient.remove(hex(echo));
            if (ctx != null) {
                HandshakeFailure f = body[KeyAgreement.RANDOM_LEN] == ERR_VERSION
                        ? HandshakeFailure.VERSION_MISMATCH
                        : HandshakeFailure.PEER_KEY_INVALID;
                stats.recordHandshakeFailed(f);
                ctx.handle.fail(f);
            }
            return;
        }
        if (body.length != HELLO2_BODY_LEN) {
            stats.recordRejected(RejectReason.MALFORMED_PACKET);
            return;
        }
        byte[] echo = Arrays.copyOfRange(body, 0, KeyAgreement.RANDOM_LEN);
        ClientHandshake ctx = pendingClient.get(hex(echo));
        if (ctx == null) {
            stats.recordRejected(RejectReason.UNKNOWN_SESSION);
            return;
        }
        byte[] serverRandom = Arrays.copyOfRange(body, KeyAgreement.RANDOM_LEN, KeyAgreement.RANDOM_LEN * 2);
        byte[] serverPubBytes = Arrays.copyOfRange(body, KeyAgreement.RANDOM_LEN * 2, KeyAgreement.RANDOM_LEN * 2 + KeyAgreement.PUBLIC_KEY_LEN);
        byte[] serverConfirm = Arrays.copyOfRange(body, KeyAgreement.RANDOM_LEN * 2 + KeyAgreement.PUBLIC_KEY_LEN, HELLO2_BODY_LEN);
        byte[] transcriptHash = KeyAgreement.sha256(ctx.helloBody, Arrays.copyOf(body, HELLO2_BODY_LEN - KeyAgreement.KEY_LEN));
        try {
            PublicKey serverPub = KeyAgreement.publicKeyFromBytes(serverPubBytes);
            byte[] shared = KeyAgreement.agree(ctx.keyPair, serverPub);
            byte[] expected = KeyAgreement.confirmationMac(shared, transcriptHash, "server".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (!constantTimeEquals(expected, serverConfirm)) {
                failClientHandshake(ctx, HandshakeFailure.TRANSCRIPT_MISMATCH);
                return;
            }
            long sessionId = KeyAgreement.deriveSessionId(shared, transcriptHash);
            byte[] chainKey = KeyAgreement.deriveChainKey(shared, transcriptHash);
            byte[] clientConfirm = KeyAgreement.confirmationMac(shared, transcriptHash, "client".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            KeyAgreement.erase(shared);
            SecureSession session = new SecureSession(sessionId, Role.CLIENT, config, chainKey, stats);
            KeyAgreement.erase(chainKey);
            sessions.put(sessionId, session);
            pendingClient.remove(hex(ctx.clientRandom));
            stats.recordHandshakeCompleted();
            ctx.handle.complete(sessionId);
            emit(new Packet(PacketType.FIN, sessionId, 0, 0L, clientConfirm));
        } catch (HandshakeException e) {
            failClientHandshake(ctx, e.failure());
        }
    }

    private void failClientHandshake(ClientHandshake ctx, HandshakeFailure failure) {
        pendingClient.remove(hex(ctx.clientRandom));
        stats.recordHandshakeFailed(failure);
        ctx.handle.fail(failure);
    }

    // ------------------------------------------------------------------
    // Handshake: server side
    // ------------------------------------------------------------------

    private void onHello(Packet packet) {
        byte[] body = packet.payload();
        if (body.length != HELLO_BODY_LEN) {
            stats.recordRejected(RejectReason.MALFORMED_PACKET);
            return;
        }
        byte[] clientRandom = Arrays.copyOfRange(body, 1, 1 + KeyAgreement.RANDOM_LEN);
        if (body[0] != KeyAgreement.VERSION) {
            stats.recordHandshakeFailed(HandshakeFailure.VERSION_MISMATCH);
            emitHandshakeError(clientRandom, ERR_VERSION);
            return;
        }
        byte[] clientPubBytes = Arrays.copyOfRange(body, 1 + KeyAgreement.RANDOM_LEN, HELLO_BODY_LEN);
        try {
            PublicKey clientPub = KeyAgreement.publicKeyFromBytes(clientPubBytes);
            KeyPair keyPair = KeyAgreement.generateKeyPair(random);
            byte[] shared = KeyAgreement.agree(keyPair, clientPub);
            byte[] serverRandom = new byte[KeyAgreement.RANDOM_LEN];
            random.nextBytes(serverRandom);
            byte[] hello2Prefix = ByteBuffer.allocate(KeyAgreement.RANDOM_LEN * 2 + KeyAgreement.PUBLIC_KEY_LEN)
                    .put(clientRandom)
                    .put(serverRandom)
                    .put(KeyAgreement.publicKeyBytes(keyPair.getPublic()))
                    .array();
            byte[] transcriptHash = KeyAgreement.sha256(body, hello2Prefix);
            byte[] serverConfirm = KeyAgreement.confirmationMac(shared, transcriptHash, "server".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            long sessionId = KeyAgreement.deriveSessionId(shared, transcriptHash);
            ServerHandshake ctx = new ServerHandshake();
            ctx.shared = shared;
            ctx.transcriptHash = transcriptHash;
            ctx.deadline = now() + config.timeoutMillis();
            pendingServer.put(sessionId, ctx);
            byte[] hello2Body = ByteBuffer.allocate(HELLO2_BODY_LEN).put(hello2Prefix).put(serverConfirm).array();
            emit(new Packet(PacketType.HELLO2, sessionId, 0, 0L, hello2Body));
        } catch (HandshakeException e) {
            stats.recordHandshakeFailed(e.failure());
            emitHandshakeError(clientRandom, ERR_PEER_KEY);
        }
    }

    private void emitHandshakeError(byte[] clientRandom, byte code) {
        byte[] err = ByteBuffer.allocate(KeyAgreement.RANDOM_LEN + 1).put(clientRandom).put(code).array();
        emit(new Packet(PacketType.HELLO2, 0L, 0, 0L, err));
    }

    private void onFin(Packet packet) {
        ServerHandshake ctx = pendingServer.remove(packet.sessionId());
        if (ctx == null) {
            stats.recordRejected(RejectReason.UNKNOWN_SESSION);
            return;
        }
        byte[] expected = KeyAgreement.confirmationMac(ctx.shared, ctx.transcriptHash, "client".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        if (!constantTimeEquals(expected, packet.payload())) {
            KeyAgreement.erase(ctx.shared);
            stats.recordHandshakeFailed(HandshakeFailure.TRANSCRIPT_MISMATCH);
            return;
        }
        byte[] chainKey = KeyAgreement.deriveChainKey(ctx.shared, ctx.transcriptHash);
        KeyAgreement.erase(ctx.shared);
        SecureSession session = new SecureSession(packet.sessionId(), Role.SERVER, config, chainKey, stats);
        KeyAgreement.erase(chainKey);
        sessions.put(packet.sessionId(), session);
        stats.recordHandshakeCompleted();
    }

    // ------------------------------------------------------------------
    // Demultiplexing
    // ------------------------------------------------------------------

    /** Entry point for every received frame. Never throws on bad input. */
    public void onBytes(byte[] frame) {
        Packet packet = PacketCodec.decode(frame);
        if (packet == null) {
            stats.recordRejected(RejectReason.MALFORMED_PACKET);
            return;
        }
        switch (packet.type()) {
            case HELLO -> onHello(packet);
            case HELLO2 -> onHello2(packet);
            case FIN -> onFin(packet);
            case DATA -> routeToSession(packet, SessionKind.DATA);
            case ROTATE -> routeToSession(packet, SessionKind.ROTATE);
            case ROTATE_ACK -> routeToSession(packet, SessionKind.ROTATE_ACK);
            case CLOSE -> routeToSession(packet, SessionKind.CLOSE);
        }
    }

    private enum SessionKind { DATA, ROTATE, ROTATE_ACK, CLOSE }

    private void routeToSession(Packet packet, SessionKind kind) {
        SecureSession session = sessions.get(packet.sessionId());
        if (session == null) {
            synchronized (closedSessions) {
                if (closedSessions.contains(packet.sessionId())) {
                    stats.recordRejected(RejectReason.STALE_SESSION);
                    return;
                }
            }
            stats.recordRejected(RejectReason.UNKNOWN_SESSION);
            return;
        }
        switch (kind) {
            case DATA -> session.onData(packet);
            case ROTATE -> session.onRotateInto(packet, p -> outbox.add(PacketCodec.encode(p)));
            case ROTATE_ACK -> session.onRotateAck(packet);
            case CLOSE -> {
                session.onClose(packet);
                forgetSession(packet.sessionId());
            }
        }
        drain();
    }

    // ------------------------------------------------------------------
    // Application API
    // ------------------------------------------------------------------

    /** Send one application message on an established session. */
    public void send(long sessionId, byte[] payload) {
        SecureSession session = requireSession(sessionId);
        session.encryptDataInto(payload, p -> outbox.add(PacketCodec.encode(p)));
        drain();
    }

    /** Next in-order message for the upper layer, or null. */
    public byte[] poll(long sessionId) {
        SecureSession session = sessions.get(sessionId);
        return session == null ? null : session.pollMessage();
    }

    /** Initiate a key rotation on an established session. */
    public void rotate(long sessionId) {
        SecureSession session = requireSession(sessionId);
        session.rotateInto(now(), p -> outbox.add(PacketCodec.encode(p)));
        drain();
    }

    public void close(long sessionId) {
        SecureSession session = sessions.get(sessionId);
        if (session == null) {
            return;
        }
        try {
            session.closeInto(p -> outbox.add(PacketCodec.encode(p)));
        } finally {
            session.close();
            forgetSession(sessionId);
        }
        drain();
    }

    /** Drive timeouts and retransmissions for handshakes and rotations. */
    public void tick() {
        long now = now();
        for (Map.Entry<String, ClientHandshake> e : pendingClient.entrySet()) {
            ClientHandshake ctx = e.getValue();
            if (now >= ctx.deadline) {
                if (ctx.retriesLeft > 0) {
                    ctx.retriesLeft--;
                    ctx.deadline = now + config.timeoutMillis();
                    emit(ctx.helloFrame);
                } else {
                    pendingClient.remove(e.getKey());
                    stats.recordHandshakeFailed(HandshakeFailure.RETRIES_EXHAUSTED);
                    ctx.handle.fail(HandshakeFailure.RETRIES_EXHAUSTED);
                }
            }
        }
        for (Map.Entry<Long, ServerHandshake> e : pendingServer.entrySet()) {
            if (now >= e.getValue().deadline) {
                pendingServer.remove(e.getKey());
                KeyAgreement.erase(e.getValue().shared);
                stats.recordHandshakeFailed(HandshakeFailure.TIMED_OUT);
            }
        }
        for (SecureSession session : sessions.values()) {
            session.onTickInto(now, p -> outbox.add(PacketCodec.encode(p)));
        }
        drain();
    }

    /** Current key epoch of a session, or -1 when unknown. Not key material. */
    public int epochOf(long sessionId) {
        SecureSession session = sessions.get(sessionId);
        return session == null ? -1 : session.currentEpoch();
    }

    public SessionState stateOf(long sessionId) {
        SecureSession session = sessions.get(sessionId);
        if (session != null) {
            return session.state();
        }
        synchronized (closedSessions) {
            return closedSessions.contains(sessionId) ? SessionState.CLOSED : null;
        }
    }

    public List<Long> sessionIds() {
        return new ArrayList<>(sessions.keySet());
    }

    public ChannelStats stats() {
        return stats;
    }

    /** New config applies to packets processed after this call only. */
    public void updateConfig(ChannelConfig config) {
        this.config = config;
        for (SecureSession session : sessions.values()) {
            session.updateConfig(config);
        }
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private SecureSession requireSession(long sessionId) {
        SecureSession session = sessions.get(sessionId);
        if (session == null) {
            throw new IllegalArgumentException("unknown session id");
        }
        return session;
    }

    private void forgetSession(long sessionId) {
        sessions.remove(sessionId);
        synchronized (closedSessions) {
            closedSessions.add(sessionId);
            while (closedSessions.size() > MAX_REMEMBERED_CLOSED_SESSIONS) {
                closedSessions.iterator().remove();
            }
        }
    }

    private void emit(byte[] frame) {
        outbox.add(frame);
        drain();
    }

    private void emit(Packet packet) {
        emit(PacketCodec.encode(packet));
    }

    /**
     * Deliver queued frames. Re-entrant calls (the peer answering
     * synchronously) simply enqueue; the outermost loop delivers everything
     * in FIFO order. Never invoked while holding a session monitor.
     */
    private void drain() {
        if (!draining.compareAndSet(false, true)) {
            return;
        }
        try {
            Consumer<byte[]> s = sink;
            if (s == null) {
                outbox.clear();
                return;
            }
            byte[] frame;
            while ((frame = outbox.poll()) != null) {
                s.accept(frame);
            }
        } finally {
            draining.set(false);
            if (!outbox.isEmpty()) {
                drain();
            }
        }
    }

    private long now() {
        return clock.getAsLong();
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        return java.security.MessageDigest.isEqual(a, b);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    private static final class ClientHandshake {
        HandshakeHandle handle;
        KeyPair keyPair;
        byte[] clientRandom;
        byte[] helloBody;
        byte[] helloFrame;
        long deadline;
        int retriesLeft;
    }

    private static final class ServerHandshake {
        byte[] shared;
        byte[] transcriptHash;
        long deadline;
    }
}
