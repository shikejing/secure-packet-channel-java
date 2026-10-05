package com.github.shikejing.securepacketchanneljava.tests;

import com.github.shikejing.securepacketchanneljava.channel.ChannelConfig;
import com.github.shikejing.securepacketchanneljava.channel.CryptoUtil;
import com.github.shikejing.securepacketchanneljava.channel.LoopbackTransport;
import com.github.shikejing.securepacketchanneljava.channel.Message;
import com.github.shikejing.securepacketchanneljava.channel.RejectReason;
import com.github.shikejing.securepacketchanneljava.channel.SecureSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/** 重复、乱序与迟到报文的处理必须确定，超出窗口的老报文不得再次被接受。 */
class ReplayWindowTest {

    private static final int WINDOW = 8;

    private InterceptingTransport clientWire;
    private SecureSession client;
    private SecureSession server;

    @BeforeEach
    void setUp() throws Exception {
        LoopbackTransport[] link = LoopbackTransport.pair();
        clientWire = new InterceptingTransport(link[0]);
        ChannelConfig cfg = ChannelConfig.builder().replayWindowSize(WINDOW).build();
        client = SecureSession.client(1L, clientWire, cfg, CryptoUtil.deterministicRandom(1L));
        server = SecureSession.server(1L, link[1], cfg, CryptoUtil.deterministicRandom(2L));
        client.startHandshake();
        server.accept();
        client.completeHandshake();
        clientWire.clearSent();
    }

    /** 抓 n 条报文（不转发），返回原始字节。 */
    private List<byte[]> capture(int n) {
        clientWire.stopForwarding();
        for (int i = 0; i < n; i++) {
            client.send(("m" + i).getBytes(StandardCharsets.UTF_8));
        }
        clientWire.resumeForwarding();
        List<byte[]> raws = clientWire.sent();
        clientWire.clearSent();
        return raws;
    }

    private List<String> drain(SecureSession s) {
        List<String> out = new ArrayList<>();
        Optional<Message> m;
        while ((m = s.pollMessage()).isPresent()) {
            out.add(new String(m.get().payload(), StandardCharsets.UTF_8));
        }
        return out;
    }

    @Test
    void duplicateIsRejectedDeterministically() {
        List<byte[]> raws = capture(1);
        clientWire.injectRaw(raws.get(0));
        clientWire.injectRaw(raws.get(0)); // 原样重放
        assertEquals(List.of("m0"), drain(server));
        assertEquals(1, server.stats().accepted());
        assertEquals(1, server.stats().rejected(RejectReason.DUPLICATE));
    }

    @Test
    void outOfOrderWithinWindowIsAcceptedInArrivalOrder() {
        List<byte[]> raws = capture(3);
        // 乱序投递：m2, m0, m1 —— 均在窗口内，全部接受，交付顺序即到达顺序（确定）。
        clientWire.injectRaw(raws.get(2));
        clientWire.injectRaw(raws.get(0));
        clientWire.injectRaw(raws.get(1));
        assertEquals(List.of("m2", "m0", "m1"), drain(server));
        assertEquals(3, server.stats().accepted());
        assertEquals(0, server.stats().totalRejected());
    }

    @Test
    void oldPacketBeyondWindowIsRejectedAndNeverAcceptedAgain() {
        List<byte[]> raws = capture(WINDOW + 2); // seq 0..WINDOW+1
        // 按序投递，窗口随 highest 正常滑动到 WINDOW+1。
        for (byte[] raw : raws) {
            clientWire.injectRaw(raw);
        }
        assertEquals(WINDOW + 2, drain(server).size());
        // seq 0 已落在窗口下界之外（highest - WINDOW = 1）。
        clientWire.injectRaw(raws.get(0));
        assertEquals(List.of(), drain(server));
        assertEquals(1, server.stats().rejected(RejectReason.SEQUENCE_TOO_OLD));
        // 再次投递同一条老报文：仍然拒绝，不会复活。
        clientWire.injectRaw(raws.get(0));
        drain(server);
        assertEquals(2, server.stats().rejected(RejectReason.SEQUENCE_TOO_OLD));
    }

    @Test
    void withinWindowLatePacketIsStillAcceptedOnce() {
        List<byte[]> raws = capture(4);
        // 先送 m3（窗口前移），再送迟到的 m1（仍在窗口内）。
        clientWire.injectRaw(raws.get(3));
        clientWire.injectRaw(raws.get(1));
        assertEquals(List.of("m3", "m1"), drain(server));
        // 迟到的 m1 再来一次：确定的重放。
        clientWire.injectRaw(raws.get(1));
        drain(server);
        assertEquals(1, server.stats().rejected(RejectReason.DUPLICATE));
    }

    @Test
    void farFutureSequenceIsRejected() {
        List<byte[]> raws = capture(1);
        clientWire.injectRaw(raws.get(0));
        drain(server);
        // 伪造一个远超窗口的序号：直接发送 WINDOW+100 条真实报文代价大，
        // 改为连续发送使窗口正常滑动后，旧报文不可再接受（见 oldPacketBeyondWindow），
        // 这里验证超前窗口边界的报文被拒绝。
        clientWire.stopForwarding();
        for (int i = 0; i < WINDOW + 100; i++) {
            client.send(("f" + i).getBytes(StandardCharsets.UTF_8));
        }
        List<byte[]> all = clientWire.sent();
        clientWire.clearSent();
        clientWire.resumeForwarding();
        // 只注入最远的一条：与 highest 的差距超过窗口，拒绝。
        clientWire.injectRaw(all.get(all.size() - 1));
        assertEquals(List.of(), drain(server));
        assertEquals(1, server.stats().rejected(RejectReason.SEQUENCE_AHEAD_OF_WINDOW));
    }

    @Test
    void windowSizeConfigChangeOnlyAffectsSubsequentPackets() {
        List<byte[]> raws = capture(4);
        clientWire.injectRaw(raws.get(3)); // highest = 3
        drain(server);
        // 把窗口缩到 2：之后 seq 0（highest-3）过老。
        server.updateConfig(ChannelConfig.builder().replayWindowSize(2).build());
        clientWire.injectRaw(raws.get(0));
        drain(server);
        assertEquals(1, server.stats().rejected(RejectReason.SEQUENCE_TOO_OLD));
        // 但 highest-1 仍在窗口内，可接受。
        clientWire.injectRaw(raws.get(2));
        assertEquals(List.of("m2"), drain(server));
    }
}
