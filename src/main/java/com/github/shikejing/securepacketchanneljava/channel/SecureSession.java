package com.github.shikejing.securepacketchanneljava.channel;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.TreeMap;

/**
 * Per-session cryptographic and ordering state. All public methods are
 * synchronized on the session monitor, so callers never observe a
 * half-processed state: each packet is either fully processed or not at all.
 *
 * Sequence numbers never go backwards within a session and are never reused
 * across key epochs; the AEAD nonce is derived deterministically from
 * (epoch, seq), so a nonce/key pair can never repeat.
 */
public final class SecureSession {

    private static final int GCM_TAG_BITS = 128;
    private static final int NONCE_LEN = 12;

    private final long sessionId;
    private final Role role;
    private final ChannelStats stats;

    private ChannelConfig config;
    private SessionState state = SessionState.ESTABLISHED;

    // Key chain: chainKey -> per-epoch traffic keys. Rotation advances the
    // chain and erases the previous link.
    private byte[] chainKey;
    private SessionKeys currentKeys;
    private SessionKeys previousKeys; // one epoch of grace for in-flight packets

    // Send counters: data and control live in separate sequence spaces.
    private long sendDataSeq;
    private long sendCtrlSeq;

    // Receive side.
    private final ReplayWindow dataWindow;
    private final ReplayWindow ctrlWindow;
    private final TreeMap<Long, byte[]> deliveryBuffer = new TreeMap<>();
    private long nextDeliverSeq;

    // Pending rotation (initiator side only).
    private int pendingEpoch = -1;
    private byte[] pendingChainKey;
    private SessionKeys pendingKeys;
    private Packet rotatePacket;
    private long rotationDeadline;
    private int rotationRetriesLeft;

    SecureSession(long sessionId, Role role, ChannelConfig config, byte[] chainKey, ChannelStats stats) {
        this.sessionId = sessionId;
        this.role = role;
        this.config = config;
        this.stats = stats;
        this.chainKey = chainKey.clone();
        this.currentKeys = KeyAgreement.deriveSessionKeys(chainKey, 0, role);
        this.dataWindow = new ReplayWindow(config.replayWindowSize());
        this.ctrlWindow = new ReplayWindow(config.replayWindowSize());
    }

    public long sessionId() {
        return sessionId;
    }

    public synchronized SessionState state() {
        return state;
    }

    public synchronized int currentEpoch() {
        return currentKeys.epoch();
    }

    // ------------------------------------------------------------------
    // Sending
    // ------------------------------------------------------------------

    /**
     * Encrypt and frame one DATA packet, handing it to {@code out} while
     * still holding the session monitor. This makes encrypt+enqueue atomic
     * with respect to key rotation commits, so a packet can never be emitted
     * under a key epoch the peer has already retired.
     */
    public synchronized void encryptDataInto(byte[] plaintext, java.util.function.Consumer<Packet> out) {
        requireUsable();
        long seq = sendDataSeq++;
        byte[] aad = headerPlaceholder(PacketType.DATA, currentKeys.epoch(), seq);
        byte[] ct = seal(currentKeys, nonce(currentKeys.epoch(), seq), plaintext, aad);
        out.accept(new Packet(PacketType.DATA, sessionId, currentKeys.epoch(), seq, ct));
    }

    // ------------------------------------------------------------------
    // Receiving
    // ------------------------------------------------------------------

    /** Process one received DATA packet. */
    public synchronized ReceiveOutcome onData(Packet packet) {
        if (state == SessionState.CLOSED) {
            return reject(RejectReason.SESSION_CLOSED);
        }
        SessionKeys keys = keysForEpoch(packet.epoch());
        if (keys == null) {
            return reject(RejectReason.STALE_EPOCH);
        }
        byte[] aad = headerPlaceholder(PacketType.DATA, packet.epoch(), packet.seq());
        byte[] plain = open(keys, nonce(packet.epoch(), packet.seq()), packet.payload(), aad);
        if (plain == null) {
            return reject(RejectReason.INTEGRITY_FAILURE);
        }
        long seq = packet.seq();
        ReplayWindow.Verdict peek = dataWindow.peek(seq);
        if (peek == ReplayWindow.Verdict.DUPLICATE) {
            return reject(RejectReason.REPLAY_DUPLICATE);
        }
        if (peek == ReplayWindow.Verdict.TOO_OLD) {
            return reject(RejectReason.TOO_OLD);
        }
        if (seq < nextDeliverSeq) {
            // Delivery point already moved past this sequence number.
            return reject(RejectReason.TOO_OLD);
        }
        if (seq - nextDeliverSeq >= config.maxInFlight()) {
            // Beyond the in-flight buffer bound; not marked, may be retried later.
            return reject(RejectReason.BUFFER_OVERFLOW);
        }
        ReplayWindow.Verdict verdict = dataWindow.checkAndMark(seq);
        if (verdict != ReplayWindow.Verdict.ACCEPTED) {
            // Cannot happen after the peek above; kept as a defensive branch.
            return reject(verdict == ReplayWindow.Verdict.DUPLICATE
                    ? RejectReason.REPLAY_DUPLICATE : RejectReason.TOO_OLD);
        }
        deliveryBuffer.put(seq, plain);
        stats.recordAccepted();
        return ReceiveOutcome.accepted();
    }

    /**
     * Next in-order message for the upper layer, or null. A gap is skipped
     * deterministically once the replay window has slid past it, because a
     * missing sequence number can never be accepted after that point; this
     * way one lost packet cannot stall the stream forever.
     */
    public synchronized byte[] pollMessage() {
        skipUnreachableGap();
        byte[] msg = deliveryBuffer.remove(nextDeliverSeq);
        if (msg != null) {
            nextDeliverSeq++;
            return msg;
        }
        return null;
    }

    private void skipUnreachableGap() {
        // Only truly missing sequence numbers may be skipped; buffered
        // messages are always delivered, even below the window floor.
        long floor = dataWindow.highest() - config.replayWindowSize() + 1;
        while (nextDeliverSeq < floor && !deliveryBuffer.containsKey(nextDeliverSeq)) {
            nextDeliverSeq++;
        }
    }

    // ------------------------------------------------------------------
    // Key rotation
    // ------------------------------------------------------------------

    /** Begin a key rotation; the ROTATE control packet is handed to {@code out}. */
    public synchronized void rotateInto(long nowMillis, java.util.function.Consumer<Packet> out) {
        if (state != SessionState.ESTABLISHED) {
            throw new IllegalStateException("cannot rotate in state " + state);
        }
        pendingEpoch = currentKeys.epoch() + 1;
        pendingChainKey = KeyAgreement.advanceChainKey(chainKey, pendingEpoch);
        pendingKeys = KeyAgreement.deriveSessionKeys(pendingChainKey, pendingEpoch, role);
        byte[] body = ByteBuffer.allocate(4).putInt(pendingEpoch).array();
        rotatePacket = encryptControl(PacketType.ROTATE, body);
        rotationRetriesLeft = config.maxRetries();
        rotationDeadline = nowMillis + config.timeoutMillis();
        state = SessionState.ROTATING;
        out.accept(rotatePacket);
    }

    /**
     * Handle a ROTATE request from the peer. On success the ROTATE_ACK is
     * handed to {@code out} inside the same critical section as the commit,
     * so no new-epoch data packet can overtake the ACK on the wire.
     */
    public synchronized ReceiveOutcome onRotateInto(Packet packet, java.util.function.Consumer<Packet> out) {
        if (state == SessionState.CLOSED) {
            return reject(RejectReason.SESSION_CLOSED);
        }
        SessionKeys keys = keysForEpoch(packet.epoch());
        if (keys == null) {
            return reject(RejectReason.STALE_EPOCH);
        }
        byte[] body = openControl(keys, packet);
        if (body == null) {
            return reject(RejectReason.INTEGRITY_FAILURE);
        }
        ReplayWindow.Verdict verdict = ctrlWindow.checkAndMark(packet.seq());
        if (verdict == ReplayWindow.Verdict.DUPLICATE) {
            return reject(RejectReason.REPLAY_DUPLICATE);
        }
        if (verdict == ReplayWindow.Verdict.TOO_OLD) {
            return reject(RejectReason.TOO_OLD);
        }
        if (body.length != 4) {
            return reject(RejectReason.MALFORMED_PACKET);
        }
        int newEpoch = ByteBuffer.wrap(body).getInt();
        if (newEpoch != currentKeys.epoch() + 1) {
            return reject(RejectReason.UNEXPECTED_CONTROL);
        }
        if (state == SessionState.ROTATING) {
            // Simultaneous rotation: the client-initiated one wins, the
            // server rolls its own attempt back. Deterministic on both sides.
            if (role == Role.CLIENT) {
                return reject(RejectReason.UNEXPECTED_CONTROL);
            }
            discardPendingRotation();
        }
        // Commit: current becomes previous (grace for in-flight packets).
        byte[] newChain = KeyAgreement.advanceChainKey(chainKey, newEpoch);
        KeyAgreement.erase(chainKey);
        chainKey = newChain;
        if (previousKeys != null) {
            previousKeys.destroy();
        }
        previousKeys = currentKeys;
        currentKeys = KeyAgreement.deriveSessionKeys(chainKey, newEpoch, role);
        // ROTATE_ACK is protected under the NEW keys and emitted atomically
        // with the commit.
        out.accept(encryptControl(PacketType.ROTATE_ACK, body));
        stats.recordRotationCommitted();
        return ReceiveOutcome.accepted();
    }

    /** Handle a ROTATE_ACK confirming our pending rotation. */
    public synchronized ReceiveOutcome onRotateAck(Packet packet) {
        if (state == SessionState.CLOSED) {
            return reject(RejectReason.SESSION_CLOSED);
        }
        if (state != SessionState.ROTATING || packet.epoch() != pendingEpoch) {
            return reject(RejectReason.UNEXPECTED_CONTROL);
        }
        byte[] body = openControl(pendingKeys, packet);
        if (body == null) {
            return reject(RejectReason.INTEGRITY_FAILURE);
        }
        ReplayWindow.Verdict verdict = ctrlWindow.checkAndMark(packet.seq());
        if (verdict == ReplayWindow.Verdict.DUPLICATE) {
            return reject(RejectReason.REPLAY_DUPLICATE);
        }
        if (verdict == ReplayWindow.Verdict.TOO_OLD) {
            return reject(RejectReason.TOO_OLD);
        }
        if (body.length != 4 || ByteBuffer.wrap(body).getInt() != pendingEpoch) {
            return reject(RejectReason.UNEXPECTED_CONTROL);
        }
        // Commit the pending epoch.
        KeyAgreement.erase(chainKey);
        chainKey = pendingChainKey;
        pendingChainKey = null;
        if (previousKeys != null) {
            previousKeys.destroy();
        }
        previousKeys = currentKeys;
        currentKeys = pendingKeys;
        pendingKeys = null;
        rotatePacket = null;
        state = SessionState.ESTABLISHED;
        stats.recordRotationCommitted();
        return ReceiveOutcome.accepted();
    }

    /**
     * Drive retransmission/timeout of a pending rotation. On timeout the
     * rotation is rolled back and the session keeps the old keys.
     * Packets due for (re)transmission are handed to {@code out}.
     */
    public synchronized void onTickInto(long nowMillis, java.util.function.Consumer<Packet> out) {
        if (state == SessionState.ROTATING && nowMillis >= rotationDeadline) {
            if (rotationRetriesLeft > 0) {
                rotationRetriesLeft--;
                rotationDeadline = nowMillis + config.timeoutMillis();
                out.accept(rotatePacket);
            } else {
                // Roll back: the peer never confirmed, so it is still on the
                // old epoch; we stay there too and the session continues.
                discardPendingRotation();
                stats.recordRotationRolledBack();
            }
        }
    }

    // ------------------------------------------------------------------
    // Close
    // ------------------------------------------------------------------

    /** Build a protected CLOSE control packet, handed to {@code out}. */
    public synchronized void closeInto(java.util.function.Consumer<Packet> out) {
        requireUsable();
        out.accept(encryptControl(PacketType.CLOSE, new byte[0]));
    }

    /** Handle a CLOSE from the peer; closes the session after verification. */
    public synchronized ReceiveOutcome onClose(Packet packet) {
        if (state == SessionState.CLOSED) {
            return reject(RejectReason.SESSION_CLOSED);
        }
        SessionKeys keys = keysForEpoch(packet.epoch());
        if (keys == null) {
            return reject(RejectReason.STALE_EPOCH);
        }
        byte[] body = openControl(keys, packet);
        if (body == null) {
            return reject(RejectReason.INTEGRITY_FAILURE);
        }
        ReplayWindow.Verdict verdict = ctrlWindow.checkAndMark(packet.seq());
        if (verdict == ReplayWindow.Verdict.DUPLICATE) {
            return reject(RejectReason.REPLAY_DUPLICATE);
        }
        if (verdict == ReplayWindow.Verdict.TOO_OLD) {
            return reject(RejectReason.TOO_OLD);
        }
        close();
        stats.recordAccepted();
        return ReceiveOutcome.accepted();
    }

    /** Install a new config; affects only packets processed after this call. */
    public synchronized void updateConfig(ChannelConfig config) {
        this.config = config;
    }

    /** Close the session and erase key material. */
    public synchronized void close() {
        state = SessionState.CLOSED;
        KeyAgreement.erase(chainKey);
        currentKeys.destroy();
        if (previousKeys != null) {
            previousKeys.destroy();
        }
        discardPendingRotation();
        deliveryBuffer.clear();
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private void discardPendingRotation() {
        if (pendingKeys != null) {
            pendingKeys.destroy();
            pendingKeys = null;
        }
        KeyAgreement.erase(pendingChainKey);
        pendingChainKey = null;
        rotatePacket = null;
        pendingEpoch = -1;
        if (state == SessionState.ROTATING) {
            state = SessionState.ESTABLISHED;
        }
    }

    private void requireUsable() {
        if (state == SessionState.CLOSED) {
            throw new IllegalStateException("session is closed");
        }
    }

    private SessionKeys keysForEpoch(int epoch) {
        if (epoch == currentKeys.epoch()) {
            return currentKeys;
        }
        if (previousKeys != null && epoch == previousKeys.epoch()) {
            return previousKeys;
        }
        return null;
    }

    private Packet encryptControl(PacketType type, byte[] body) {
        long seq = sendCtrlSeq++;
        byte[] aad = headerPlaceholder(type, currentKeys.epoch(), seq);
        byte[] ct = seal(currentKeys, nonce(currentKeys.epoch(), seq), body, aad);
        return new Packet(type, sessionId, currentKeys.epoch(), seq, ct);
    }

    private byte[] openControl(SessionKeys keys, Packet packet) {
        byte[] aad = headerPlaceholder(packet.type(), packet.epoch(), packet.seq());
        return open(keys, nonce(packet.epoch(), packet.seq()), packet.payload(), aad);
    }

    /** Header bytes exactly as they will appear on the wire (used as AAD). */
    private byte[] headerPlaceholder(PacketType type, int epoch, long seq) {
        return PacketCodec.headerOf(PacketCodec.encode(new Packet(type, sessionId, epoch, seq, new byte[0])));
    }

    static byte[] nonce(int epoch, long seq) {
        ByteBuffer buf = ByteBuffer.allocate(NONCE_LEN);
        buf.putInt(epoch);
        buf.putLong(seq);
        return buf.array();
    }

    private static byte[] seal(SessionKeys keys, byte[] nonce, byte[] plaintext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keys.sendKey(), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES/GCM not available", e);
        }
    }

    /** @return plaintext, or null when verification fails. */
    private static byte[] open(SessionKeys keys, byte[] nonce, byte[] ciphertext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keys.recvKey(), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    private ReceiveOutcome reject(RejectReason reason) {
        stats.recordRejected(reason);
        return ReceiveOutcome.rejected(reason);
    }

    @Override
    public String toString() {
        // Never include key material.
        return "SecureSession{id=" + sessionId + ", state=" + state + ", epoch=" + currentKeys.epoch() + "}";
    }
}
