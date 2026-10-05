package com.github.shikejing.securepacketchanneljava.channel;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话注册表：管理本进程内多个并发会话。
 * 每个 {@link SecureSession} 自带内部锁，会话之间不共享可变状态，
 * 单个会话的异常输入或掉线不会影响其他会话。
 */
public final class SessionManager {
    private final Map<Long, SecureSession> sessions = new ConcurrentHashMap<>();

    /** 注册会话；同一会话标识重复注册会失败。 */
    public boolean register(SecureSession session) {
        return sessions.putIfAbsent(session.sessionId(), session) == null;
    }

    public Optional<SecureSession> get(long sessionId) {
        return Optional.ofNullable(sessions.get(sessionId));
    }

    /** 关闭并移除会话；不影响其他会话。 */
    public void remove(long sessionId) {
        SecureSession s = sessions.remove(sessionId);
        if (s != null) s.close();
    }

    public List<Long> sessionIds() {
        return new ArrayList<>(sessions.keySet());
    }

    /** 聚合所有会话的统计快照（每个快照本身是不可变副本）。 */
    public Map<Long, ChannelStats.Snapshot> statsSnapshot() {
        Map<Long, ChannelStats.Snapshot> out = new ConcurrentHashMap<>();
        sessions.forEach((id, s) -> out.put(id, s.stats()));
        return out;
    }

    /** 便捷构造：创建一对已通过内存管道完成握手的会话（客户端 + 服务端）。 */
    public static SecureSession[] establishedPair(long sessionId, ChannelConfig config, long clientSeed, long serverSeed) {
        LoopbackTransport[] pair = LoopbackTransport.pair();
        SecureSession client = SecureSession.client(sessionId, pair[0], config, CryptoUtil.deterministicRandom(clientSeed));
        SecureSession server = SecureSession.server(sessionId, pair[1], config, CryptoUtil.deterministicRandom(serverSeed));
        client.startHandshake();
        try {
            server.accept();
            client.completeHandshake();
        } catch (HandshakeException e) {
            throw new IllegalStateException("in-process handshake should not fail", e);
        }
        return new SecureSession[]{client, server};
    }
}
