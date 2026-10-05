package com.github.shikejing.securepacketchanneljava.tests;

import com.github.shikejing.securepacketchanneljava.channel.ChannelConfig;
import com.github.shikejing.securepacketchanneljava.channel.CryptoUtil;
import com.github.shikejing.securepacketchanneljava.channel.LoopbackTransport;
import com.github.shikejing.securepacketchanneljava.channel.Message;
import com.github.shikejing.securepacketchanneljava.channel.SecureSession;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/** 固定随机种子与相同输入序列下，线上字节与交付结果必须逐条一致。 */
class DeterminismTest {

    /** 运行一段固定脚本，返回可观测轨迹（线上字节 + 交付消息 + 统计）。 */
    private static List<String> runScenario() throws Exception {
        List<String> trace = new ArrayList<>();
        LoopbackTransport[] link = LoopbackTransport.pair();
        InterceptingTransport wire = new InterceptingTransport(link[0]);
        ChannelConfig cfg = ChannelConfig.defaults();
        SecureSession client = SecureSession.client(42L, wire, cfg, CryptoUtil.deterministicRandom(777L));
        SecureSession server = SecureSession.server(42L, link[1], cfg, CryptoUtil.deterministicRandom(888L));

        client.startHandshake();
        server.accept();
        client.completeHandshake();

        for (int i = 0; i < 5; i++) {
            client.send(("phase1-" + i).getBytes(StandardCharsets.UTF_8));
        }
        client.initiateRotation();
        drain(server, trace);   // 交付 phase1 并处理 ROTATE
        client.pollMessage();   // 处理 COMMIT，轮换完成
        for (int i = 0; i < 3; i++) {
            client.send(("phase2-" + i).getBytes(StandardCharsets.UTF_8));
        }
        drain(server, trace);

        // 断线重连
        LoopbackTransport[] link2 = LoopbackTransport.pair();
        InterceptingTransport wire2 = new InterceptingTransport(link2[0]);
        client.startReconnect(wire2);
        server.attachTransport(link2[1]);
        server.pollMessage();
        client.completeHandshake();
        for (int i = 0; i < 2; i++) {
            client.send(("phase3-" + i).getBytes(StandardCharsets.UTF_8));
        }
        drain(server, trace);

        for (byte[] b : wire.sent()) {
            trace.add("wire1:" + HexFormat.of().formatHex(b));
        }
        for (byte[] b : wire2.sent()) {
            trace.add("wire2:" + HexFormat.of().formatHex(b));
        }
        trace.add("stats:" + server.stats());
        return trace;
    }

    private static void drain(SecureSession server, List<String> trace) {
        Optional<Message> m;
        while ((m = server.pollMessage()).isPresent()) {
            trace.add("deliver:seq=" + m.get().sequence() + ",epoch=" + m.get().keyEpoch()
                    + ",body=" + new String(m.get().payload(), StandardCharsets.UTF_8));
        }
    }

    @Test
    void sameSeedSameInputsProduceIdenticalTrace() throws Exception {
        List<String> run1 = runScenario();
        List<String> run2 = runScenario();
        assertEquals(run1, run2, "固定种子与相同输入下，线上字节与交付结果必须逐条一致");
        // 脚本确实覆盖了握手、数据、轮换与重连，不是空轨迹。
        assertTrue(run1.stream().anyMatch(l -> l.startsWith("deliver:")));
        assertTrue(run1.stream().anyMatch(l -> l.contains("epoch=1")));
        assertTrue(run1.stream().anyMatch(l -> l.startsWith("wire2:")));
    }

    @Test
    void differentSeedsProduceDifferentCiphertexts() throws Exception {
        List<String> run1 = runScenario();
        // 改一个种子，线上字节必须不同（密钥独立）。
        LoopbackTransport[] link = LoopbackTransport.pair();
        InterceptingTransport wire = new InterceptingTransport(link[0]);
        ChannelConfig cfg = ChannelConfig.defaults();
        SecureSession client = SecureSession.client(42L, wire, cfg, CryptoUtil.deterministicRandom(999L));
        SecureSession server = SecureSession.server(42L, link[1], cfg, CryptoUtil.deterministicRandom(888L));
        client.startHandshake();
        server.accept();
        client.completeHandshake();
        client.send("phase1-0".getBytes(StandardCharsets.UTF_8));
        String otherHex = HexFormat.of().formatHex(wire.lastSent());
        assertFalse(run1.contains("wire1:" + otherHex), "不同种子的密文不得相同");
    }
}
