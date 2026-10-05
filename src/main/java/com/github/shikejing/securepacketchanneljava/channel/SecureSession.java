package com.github.shikejing.securepacketchanneljava.channel;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 会话级加密与完整性通道的一端。收发两端仅通过 {@link Transport}（进程内回环/内存管道）交互。
 *
 * <p>语义要点：
 * <ul>
 *   <li>每个会话、每个会话代（重连）都重新协商独立的会话密钥；密钥材料不出现在任何日志与异常中。</li>
 *   <li>每条报文 Encrypt-then-MAC，篡改必在校验阶段拒绝，明文不会交给上层。</li>
 *   <li>序号 + 滑动重放窗口，重复/乱序/迟到处理确定，拒绝原因可区分。</li>
 *   <li>密钥轮换期间新旧两代密钥同时可收，在途报文不丢失；失败回退到上一代密钥。</li>
 *   <li>断线重连通过 RESUME 恢复，序号只前进不回退，旧会话代报文一律拒绝。</li>
 *   <li>所有状态变更都在内部锁内完成，上层永远读不到半处理状态。</li>
 * </ul>
 */
public final class SecureSession {
    public enum Role { CLIENT, SERVER }
    public enum State { NEW, HANDSHAKING, ESTABLISHED, ROTATING, CLOSED }

    private static final int KEPT_EPOCHS = 2;

    private final Object lock = new Object();
    private final long sessionId;
    private final Role role;
    private final SecureRandom random;
    private final ChannelStats stats = new ChannelStats();

    private volatile ChannelConfig config;
    private volatile Transport transport;
    private volatile State state = State.NEW;

    private int generation = 0;
    private long sendSeq = 0;
    private ReplayWindow recvWindow;
    private int sendEpoch = 0;
    private KeyMaterial sendKey;
    private final Map<Integer, KeyMaterial> recvKeys = new HashMap<>();
    private int maxRecvEpoch = -1;
    private byte[] rotationSecret;
    private KeyPair pendingKeyPair;
    private int pendingRotationEpoch = -1;
    private long pendingRotationNonce;
    private int prevSendEpoch = -1;
    private KeyMaterial prevSendKey;
    private long handshakeDeadlineNanos;
    private int handshakeRetriesLeft;
    private final ArrayDeque<Message> deliveryQueue = new ArrayDeque<>();

    private SecureSession(long sessionId, Role role, Transport transport, ChannelConfig config, SecureRandom random) {
        this.sessionId = sessionId;
        this.role = role;
        this.transport = transport;
        this.config = config;
        this.random = random;
        this.recvWindow = new ReplayWindow(config.replayWindowSize());
    }

    public static SecureSession client(long sessionId, Transport transport, ChannelConfig config, SecureRandom random) {
        return new SecureSession(sessionId, Role.CLIENT, transport, config, random);
    }

    public static SecureSession server(long sessionId, Transport transport, ChannelConfig config, SecureRandom random) {
        return new SecureSession(sessionId, Role.SERVER, transport, config, random);
    }

    // ---------------- 握手 ----------------

    /** 客户端：发送 HELLO，进入 HANDSHAKING。 */
    public void startHandshake() {
        synchronized (lock) {
            ensureState(State.NEW, "startHandshake");
            pendingKeyPair = CryptoUtil.generateX25519(random);
            byte[] hello = ControlCodec.encodeHello(ControlCodec.HELLO, sessionId, generation, 0, 0,
                    CryptoUtil.encodePublic(pendingKeyPair.getPublic()));
            transport.send(PacketCodec.encodeControl(0, hello));
            armHandshakeTimer();
            state = State.HANDSHAKING;
        }
    }

    /** 客户端：等待 HELLO_ACK/RESUME_ACK，超时按配置重试。 */
    public void completeHandshake() throws HandshakeException {
        while (true) {
            Optional<byte[]> inbound = transport.poll();
            if (inbound.isPresent()) {
                Optional<HandshakeFailure> failure = handleHandshakePacket(inbound.get());
                if (failure != null) {
                    if (failure.isEmpty()) return; // 成功
                    throw new HandshakeException(failure.get(), null);
                }
            }
            synchronized (lock) {
                if (state == State.ESTABLISHED) return;
                if (System.nanoTime() >= handshakeDeadlineNanos) {
                    if (handshakeRetriesLeft-- <= 0) {
                        state = State.NEW;
                        throw new HandshakeException(HandshakeFailure.TIMEOUT, "peer did not respond");
                    }
                    resendHandshakeLocked();
                }
            }
            Thread.yield();
        }
    }

    /** 客户端便捷方法：start + complete。需要对方并发地泵取报文。 */
    public void connect() throws HandshakeException {
        startHandshake();
        completeHandshake();
    }

    /** 服务端：等待并处理 HELLO，回复 HELLO_ACK。 */
    public void accept() throws HandshakeException {
        synchronized (lock) {
            ensureState(State.NEW, "accept");
            state = State.HANDSHAKING;
        }
        long deadline = System.nanoTime() + config.handshakeTimeoutMillis() * 1_000_000L;
        while (System.nanoTime() < deadline) {
            Optional<byte[]> inbound = transport.poll();
            if (inbound.isPresent()) {
                byte[] raw = inbound.get();
                if (raw.length >= 4
                        && (((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF)) == (PacketCodec.MAGIC & 0xFFFF)
                        && raw[2] != PacketCodec.VERSION) {
                    synchronized (lock) { state = State.NEW; }
                    throw new HandshakeException(HandshakeFailure.UNSUPPORTED_VERSION, null);
                }
                Optional<PacketCodec.Parsed> parsed = PacketCodec.decode(raw);
                if (parsed.isEmpty() || !parsed.get().isControl()) continue;
                Optional<ControlCodec.Hello> hello = ControlCodec.decodeHello(parsed.get().ciphertext());
                if (hello.isEmpty() || hello.get().kind() != ControlCodec.HELLO) {
                    throw new HandshakeException(HandshakeFailure.MALFORMED_HELLO, null);
                }
                if (hello.get().sessionId() != sessionId) {
                    throw new HandshakeException(HandshakeFailure.SESSION_MISMATCH, null);
                }
                synchronized (lock) {
                    establishFromHelloLocked(hello.get());
                    state = State.ESTABLISHED;
                }
                return;
            }
            Thread.yield();
        }
        synchronized (lock) { state = State.NEW; }
        throw new HandshakeException(HandshakeFailure.TIMEOUT, "no hello received");
    }

    private void establishFromHelloLocked(ControlCodec.Hello hello) {
        try {
            // 服务端收到 HELLO：生成己方临时密钥对，与客户端公钥协商，并回复 HELLO_ACK。
            pendingKeyPair = CryptoUtil.generateX25519(random);
            byte[] shared = CryptoUtil.agree(pendingKeyPair.getPrivate(), ControlCodec.copyPublicKey(hello));
            installMasterLocked(shared, hello.generation(),
                    ControlCodec.copyPublicKey(hello), CryptoUtil.encodePublic(pendingKeyPair.getPublic()));
            byte[] ack = ControlCodec.encodeHello(ControlCodec.HELLO_ACK, sessionId, hello.generation(), 0, 0,
                    CryptoUtil.encodePublic(pendingKeyPair.getPublic()));
            transport.send(PacketCodec.encodeControl(0, ack));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("key agreement failure", e);
        }
    }

    private void establishFromAckLocked(ControlCodec.Hello ack) {
        try {
            // 客户端收到 HELLO_ACK/RESUME_ACK：用在 startHandshake/startReconnect 中生成的密钥对协商。
            byte[] shared = CryptoUtil.agree(pendingKeyPair.getPrivate(), ControlCodec.copyPublicKey(ack));
            installMasterLocked(shared, ack.generation(),
                    CryptoUtil.encodePublic(pendingKeyPair.getPublic()), ControlCodec.copyPublicKey(ack));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("key agreement failure", e);
        }
    }

    /** 返回值：null 表示该报文不是握手应答（忽略）；empty 表示成功；否则为失败原因。 */
    private Optional<HandshakeFailure> handleHandshakePacket(byte[] bytes) {
        Optional<PacketCodec.Parsed> parsed = PacketCodec.decode(bytes);
        if (parsed.isEmpty() || !parsed.get().isControl()) return null;
        byte[] payload = parsed.get().ciphertext();
        if (payload.length == 0) return null;
        synchronized (lock) {
            if (state != State.HANDSHAKING) return null;
            if (payload[0] == ControlCodec.RESUME_REJECT) {
                return ControlCodec.decodeResumeReject(payload).map(Optional::of).orElse(null);
            }
            Optional<ControlCodec.Hello> ack = ControlCodec.decodeHello(payload);
            if (ack.isEmpty()) return null;
            ControlCodec.Hello h = ack.get();
            boolean expectAck = h.kind() == (generation == 0 ? ControlCodec.HELLO_ACK : ControlCodec.RESUME_ACK);
            if (!expectAck) return null;
            if (h.sessionId() != sessionId) return Optional.of(HandshakeFailure.SESSION_MISMATCH);
            if (h.generation() != generation) return Optional.of(HandshakeFailure.SESSION_MISMATCH);
            if (generation > 0) {
                // 恢复校验：对端不得声称收到我未发的序号，也不得回退我已接收的序号。
                if (h.lastRecv() >= sendSeq || h.lastSent() <= recvWindow.highest()) {
                    return Optional.of(HandshakeFailure.INVALID_RESUME_STATE);
                }
                sendSeq = Math.max(sendSeq, h.lastRecv() + 1);
            }
            establishFromAckLocked(h);
            state = State.ESTABLISHED;
            return Optional.empty();
        }
    }

    private void resendHandshakeLocked() {
        byte[] hello = ControlCodec.encodeHello(
                generation == 0 ? ControlCodec.HELLO : ControlCodec.RESUME,
                sessionId, generation, sendSeq, recvWindow.highest(),
                CryptoUtil.encodePublic(pendingKeyPair.getPublic()));
        transport.send(PacketCodec.encodeControl(0, hello));
        // 只重置截止时间，不重置剩余重试次数。
        handshakeDeadlineNanos = System.nanoTime() + config.handshakeTimeoutMillis() * 1_000_000L;
    }

    private void armHandshakeTimer() {
        handshakeDeadlineNanos = System.nanoTime() + config.handshakeTimeoutMillis() * 1_000_000L;
        handshakeRetriesLeft = config.maxHandshakeRetries();
    }

    /** 由共享密钥与交换记录派生本代全部密钥；密钥代从头开始，旧代密钥全部废弃。 */
    private void installMasterLocked(byte[] shared, int gen, byte[] clientPub, byte[] serverPub) {
        byte[] transcript = sha256(ByteBuffer.allocate(8 + 4 + clientPub.length + serverPub.length)
                .putLong(sessionId).putInt(gen).put(clientPub).put(serverPub).array());
        byte[] master = CryptoUtil.hkdf(shared, transcript, "spc-master".getBytes(StandardCharsets.UTF_8), 64);
        this.rotationSecret = CryptoUtil.hkdf(shared, transcript, "spc-rotation".getBytes(StandardCharsets.UTF_8), 32);
        recvKeys.clear();
        maxRecvEpoch = -1;
        sendEpoch = 0;
        pendingRotationEpoch = -1;
        installEpochLocked(0, master);
        this.generation = gen;
    }

    /** 安装 epoch 密钥：block 前 32 字节为 client→server，后 32 字节为 server→client。 */
    private void installEpochLocked(int epoch, byte[] block) {
        KeyMaterial mine = CryptoUtil.keyMaterial(block, role == Role.CLIENT);
        KeyMaterial theirs = CryptoUtil.keyMaterial(block, role != Role.CLIENT);
        if (epoch == sendEpoch || epoch > sendEpoch) {
            sendEpoch = epoch;
            sendKey = mine;
        }
        recvKeys.put(epoch, theirs);
        maxRecvEpoch = Math.max(maxRecvEpoch, epoch);
        while (recvKeys.size() > KEPT_EPOCHS) {
            recvKeys.keySet().stream().min(Integer::compareTo).ifPresent(recvKeys::remove);
        }
    }

    private byte[] epochBlock(int epoch) {
        return CryptoUtil.hkdf(rotationSecret, ("epoch-" + epoch).getBytes(StandardCharsets.UTF_8),
                "spc-epoch".getBytes(StandardCharsets.UTF_8), 64);
    }

    // ---------------- 断线重连 ----------------

    /** 客户端：换用新传输并发起 RESUME。 */
    public void startReconnect(Transport newTransport) {
        synchronized (lock) {
            if (state != State.ESTABLISHED && state != State.ROTATING) {
                throw new IllegalStateException("reconnect requires established session");
            }
            transport.close();
            transport = newTransport;
            generation++;
            pendingKeyPair = CryptoUtil.generateX25519(random);
            resendHandshakeLocked();
            state = State.HANDSHAKING;
        }
    }

    public void reconnect(Transport newTransport) throws HandshakeException {
        startReconnect(newTransport);
        completeHandshake();
    }

    /** 服务端/对端：链路重建后挂接新传输，随后在正常接收路径里处理 RESUME。 */
    public void attachTransport(Transport newTransport) {
        synchronized (lock) {
            transport.close();
            transport = newTransport;
        }
    }

    // ---------------- 发送 ----------------

    /** 加密并发送一条报文，返回分配的序号。 */
    public long send(byte[] payload) {
        ChannelConfig cfg;
        Transport t;
        long seq;
        int epoch;
        KeyMaterial key;
        synchronized (lock) {
            if (state == State.CLOSED) throw new IllegalStateException("session closed");
            if (state != State.ESTABLISHED && state != State.ROTATING) {
                throw new IllegalStateException("session not established");
            }
            cfg = config;
            t = transport;
            seq = sendSeq++;
            epoch = sendEpoch;
            key = sendKey;
        }
        byte[] nonce = CryptoUtil.nonce(key.noncePrefix(), seq);
        byte[] ctAndTag = CryptoUtil.encrypt(key.encKey(), nonce, epoch, seq, payload);
        byte[] ct = new byte[ctAndTag.length - CryptoUtil.TAG_LEN];
        byte[] tag = new byte[CryptoUtil.TAG_LEN];
        System.arraycopy(ctAndTag, 0, ct, 0, ct.length);
        System.arraycopy(ctAndTag, ct.length, tag, 0, tag.length);
        t.send(PacketCodec.encodeData(new Packet(epoch, seq, nonce, ct, tag)));
        stats.recordSent();
        return seq;
    }

    // ---------------- 接收 ----------------

    /**
     * 处理当前所有已到达的入站报文，并返回一条可交付消息（若有）。
     * 解密成功的消息先进入容量为 maxInFlight 的交付队列，超出上界的报文以
     * BUFFER_FULL 拒绝；被篡改/重放/过老的报文在此被拒绝并计入统计，不会交给上层。
     */
    public Optional<Message> pollMessage() {
        synchronized (lock) {
            Message queued = deliveryQueue.poll();
            if (queued != null) return Optional.of(queued);
        }
        // 成批处理已到达报文：交付队列的上界对突发流量生效。
        while (transport.poll().map(this::handlePacketAndContinue).orElse(false)) {
            // 持续处理直到传输层排空
        }
        synchronized (lock) {
            return Optional.ofNullable(deliveryQueue.poll());
        }
    }

    private boolean handlePacketAndContinue(byte[] bytes) {
        handlePacket(bytes);
        return true;
    }

    /** 处理全部已到达报文，返回本次交付的消息数。 */
    public int drainInbound() {
        int delivered = 0;
        while (pollMessage().isPresent()) delivered++;
        return delivered;
    }

    private void handlePacket(byte[] bytes) {
        Optional<PacketCodec.Parsed> parsed = PacketCodec.decode(bytes);
        if (parsed.isEmpty()) {
            stats.recordReject(RejectReason.MALFORMED);
            return;
        }
        PacketCodec.Parsed p = parsed.get();
        if (p.isControl()) {
            handleControl(p.ciphertext());
            return;
        }
        handleData(p.toDataPacket());
    }

    private void handleData(Packet p) {
        synchronized (lock) {
            if (state == State.CLOSED) { stats.recordReject(RejectReason.SESSION_CLOSED); return; }
            if (state != State.ESTABLISHED && state != State.ROTATING) {
                stats.recordReject(RejectReason.SESSION_NOT_ESTABLISHED);
                return;
            }
            KeyMaterial key = recvKeys.get(p.keyEpoch());
            if (key == null) {
                stats.recordReject(p.keyEpoch() < maxRecvEpoch ? RejectReason.STALE_EPOCH : RejectReason.MALFORMED);
                return;
            }
            ReplayWindow.Verdict verdict = recvWindow.classify(p.sequence());
            switch (verdict) {
                case TOO_OLD -> { stats.recordReject(RejectReason.SEQUENCE_TOO_OLD); return; }
                case DUPLICATE -> { stats.recordReject(RejectReason.DUPLICATE); return; }
                case ACCEPT_NEW -> {
                    if (p.sequence() - recvWindow.highest() > config.replayWindowSize()) {
                        stats.recordReject(RejectReason.SEQUENCE_AHEAD_OF_WINDOW);
                        return;
                    }
                }
                case ACCEPT_WITHIN_WINDOW -> { /* 继续校验 */ }
            }
            if (deliveryQueue.size() >= config.maxInFlight()) {
                stats.recordReject(RejectReason.BUFFER_FULL);
                return;
            }
            byte[] ctAndTag = new byte[p.ciphertext().length + p.tag().length];
            System.arraycopy(p.ciphertext(), 0, ctAndTag, 0, p.ciphertext().length);
            System.arraycopy(p.tag(), 0, ctAndTag, p.ciphertext().length, p.tag().length);
            byte[] plain = CryptoUtil.decrypt(key.encKey(), p.nonce(), p.keyEpoch(), p.sequence(), ctAndTag);
            if (plain == null) {
                stats.recordReject(RejectReason.INTEGRITY_FAILURE);
                return;
            }
            recvWindow.mark(p.sequence());
            deliveryQueue.offer(new Message(p.sequence(), p.keyEpoch(), plain));
            stats.recordAccepted();
        }
    }

    // ---------------- 控制报文 ----------------

    private void handleControl(byte[] payload) {
        if (payload.length == 0) { stats.recordReject(RejectReason.MALFORMED); return; }
        switch (payload[0]) {
            case ControlCodec.RESUME -> handleResume(payload);
            case ControlCodec.ROTATE -> handleRotate(payload);
            case ControlCodec.ROTATE_COMMIT -> handleRotateCommit(payload);
            case ControlCodec.ROTATE_ABORT -> handleRotateAbort(payload);
            default -> { /* HELLO/ACK 在握手流程外到达：忽略 */ }
        }
    }

    private void handleResume(byte[] payload) {
        Optional<ControlCodec.Hello> parsed = ControlCodec.decodeHello(payload);
        if (parsed.isEmpty()) { stats.recordReject(RejectReason.MALFORMED); return; }
        ControlCodec.Hello resume = parsed.get();
        synchronized (lock) {
            if (state != State.ESTABLISHED && state != State.ROTATING) return;
            if (resume.sessionId() != sessionId || resume.generation() <= generation) {
                stats.recordReject(RejectReason.STALE_GENERATION);
                transport.send(PacketCodec.encodeControl(0,
                        ControlCodec.encodeResumeReject(HandshakeFailure.SESSION_MISMATCH)));
                return;
            }
            if (resume.lastSent() <= recvWindow.highest() || resume.lastRecv() >= sendSeq) {
                stats.recordReject(RejectReason.STALE_GENERATION);
                transport.send(PacketCodec.encodeControl(0,
                        ControlCodec.encodeResumeReject(HandshakeFailure.INVALID_RESUME_STATE)));
                return;
            }
            // 采用双方一致的新序号基线：只前进，不回退。
            sendSeq = Math.max(sendSeq, resume.lastRecv() + 1);
            try {
                pendingKeyPair = CryptoUtil.generateX25519(random);
                byte[] shared = CryptoUtil.agree(pendingKeyPair.getPrivate(), ControlCodec.copyPublicKey(resume));
                installMasterLocked(shared, resume.generation(),
                        ControlCodec.copyPublicKey(resume), CryptoUtil.encodePublic(pendingKeyPair.getPublic()));
            } catch (java.security.GeneralSecurityException e) {
                transport.send(PacketCodec.encodeControl(0,
                        ControlCodec.encodeResumeReject(HandshakeFailure.MALFORMED_HELLO)));
                return;
            }
            byte[] ack = ControlCodec.encodeHello(ControlCodec.RESUME_ACK, sessionId, generation,
                    sendSeq, recvWindow.highest(), CryptoUtil.encodePublic(pendingKeyPair.getPublic()));
            transport.send(PacketCodec.encodeControl(0, ack));
            state = State.ESTABLISHED;
        }
    }

    private void handleRotate(byte[] payload) {
        Optional<ControlCodec.Rotate> parsed = ControlCodec.decodeRotate(payload);
        if (parsed.isEmpty() || parsed.get().kind() != ControlCodec.ROTATE) {
            stats.recordReject(RejectReason.MALFORMED);
            return;
        }
        ControlCodec.Rotate rotate = parsed.get();
        synchronized (lock) {
            if (state != State.ESTABLISHED && state != State.ROTATING) return;
            if (rotate.newEpoch() <= maxRecvEpoch) {
                transport.send(PacketCodec.encodeControl(0,
                        ControlCodec.encodeRotate(ControlCodec.ROTATE_ABORT, rotate.newEpoch(), rotate.nonce())));
                return;
            }
            if (state == State.ROTATING && pendingRotationNonce > rotate.nonce()) {
                // 同时发起轮换：nonce 大者胜出，拒绝对方。
                transport.send(PacketCodec.encodeControl(0,
                        ControlCodec.encodeRotate(ControlCodec.ROTATE_ABORT, rotate.newEpoch(), rotate.nonce())));
                return;
            }
            if (state == State.ROTATING) {
                rollbackRotationLocked(); // 己方让步
            }
            prevSendEpoch = sendEpoch;
            prevSendKey = sendKey;
            byte[] block = epochBlock(rotate.newEpoch());
            installEpochLocked(rotate.newEpoch(), block);
            transport.send(PacketCodec.encodeControl(0,
                    ControlCodec.encodeRotate(ControlCodec.ROTATE_COMMIT, rotate.newEpoch(), rotate.nonce())));
        }
    }

    private void handleRotateCommit(byte[] payload) {
        Optional<ControlCodec.Rotate> parsed = ControlCodec.decodeRotate(payload);
        if (parsed.isEmpty() || parsed.get().kind() != ControlCodec.ROTATE_COMMIT) {
            stats.recordReject(RejectReason.MALFORMED);
            return;
        }
        ControlCodec.Rotate commit = parsed.get();
        synchronized (lock) {
            if (state != State.ROTATING) return;
            if (commit.newEpoch() != pendingRotationEpoch || commit.nonce() != pendingRotationNonce) {
                rollbackRotationLocked();
                return;
            }
            installEpochLocked(pendingRotationEpoch, epochBlock(pendingRotationEpoch));
            pendingRotationEpoch = -1;
            state = State.ESTABLISHED;
            stats.recordRotation();
        }
    }

    private void handleRotateAbort(byte[] payload) {
        Optional<ControlCodec.Rotate> parsed = ControlCodec.decodeRotate(payload);
        if (parsed.isEmpty() || parsed.get().kind() != ControlCodec.ROTATE_ABORT) return;
        synchronized (lock) {
            if (state == State.ROTATING && parsed.get().newEpoch() == pendingRotationEpoch) {
                // 己方发起的轮换被对方拒绝：回退，会话继续用旧密钥。
                rollbackRotationLocked();
                return;
            }
            if (parsed.get().newEpoch() == sendEpoch && prevSendKey != null) {
                // 对方撤回了我们已接受的轮换：发送侧回退到上一代密钥。
                sendEpoch = prevSendEpoch;
                sendKey = prevSendKey;
                prevSendKey = null;
                prevSendEpoch = -1;
                stats.recordRotationRollback();
            }
        }
    }

    private void rollbackRotationLocked() {
        pendingRotationEpoch = -1;
        state = State.ESTABLISHED;
        stats.recordRotationRollback();
    }

    /** 发起一次密钥轮换。在途报文不受影响：旧密钥在切换期间继续被接受。 */
    public boolean initiateRotation() {
        synchronized (lock) {
            if (state != State.ESTABLISHED) return false;
            pendingRotationEpoch = sendEpoch + 1;
            pendingRotationNonce = random.nextLong();
            state = State.ROTATING;
            transport.send(PacketCodec.encodeControl(0,
                    ControlCodec.encodeRotate(ControlCodec.ROTATE, pendingRotationEpoch, pendingRotationNonce)));
            return true;
        }
    }

    /** 主动中止进行中的轮换，回退到上一代密钥，会话继续。 */
    public boolean abortRotation() {
        synchronized (lock) {
            if (state != State.ROTATING) return false;
            int epoch = pendingRotationEpoch;
            long nonce = pendingRotationNonce;
            rollbackRotationLocked();
            transport.send(PacketCodec.encodeControl(0,
                    ControlCodec.encodeRotate(ControlCodec.ROTATE_ABORT, epoch, nonce)));
            return true;
        }
    }

    // ---------------- 配置与状态 ----------------

    /** 原子替换配置：只影响后续报文，进行中的处理不会读到半更新状态。 */
    public void updateConfig(ChannelConfig newConfig) {
        synchronized (lock) {
            config = newConfig;
            recvWindow = recvWindow.withSize(newConfig.replayWindowSize());
        }
    }

    public ChannelStats.Snapshot stats() {
        return stats.snapshot();
    }

    public State state() { return state; }
    public int generation() { synchronized (lock) { return generation; } }
    public int currentSendEpoch() { synchronized (lock) { return sendEpoch; } }
    public long sessionId() { return sessionId; }

    public void close() {
        synchronized (lock) {
            state = State.CLOSED;
            deliveryQueue.clear();
        }
        // 关闭前把未处理的入站报文计为 SESSION_CLOSED 拒绝，保证统计自洽。
        while (transport.poll().isPresent()) {
            stats.recordReject(RejectReason.SESSION_CLOSED);
        }
        transport.close();
    }

    private void ensureState(State expected, String op) {
        if (state != expected) {
            throw new IllegalStateException(op + " requires state " + expected + " but was " + state);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
