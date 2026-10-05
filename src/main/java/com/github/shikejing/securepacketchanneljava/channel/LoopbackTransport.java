package com.github.shikejing.securepacketchanneljava.channel;

import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * 进程内内存管道。{@link #pair()} 返回一对互通的端点，
 * 一端 send 的字节可在另一端 poll 到，模拟断线重连时直接新建一对即可。
 */
public final class LoopbackTransport implements Transport {
    private final ConcurrentLinkedQueue<byte[]> inbound;
    private final ConcurrentLinkedQueue<byte[]> outbound;
    private volatile boolean open = true;

    private LoopbackTransport(ConcurrentLinkedQueue<byte[]> inbound, ConcurrentLinkedQueue<byte[]> outbound) {
        this.inbound = inbound;
        this.outbound = outbound;
    }

    public static LoopbackTransport[] pair() {
        ConcurrentLinkedQueue<byte[]> a2b = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<byte[]> b2a = new ConcurrentLinkedQueue<>();
        return new LoopbackTransport[]{new LoopbackTransport(b2a, a2b), new LoopbackTransport(a2b, b2a)};
    }

    @Override
    public void send(byte[] bytes) {
        if (open) {
            outbound.offer(bytes);
        }
    }

    @Override
    public Optional<byte[]> poll() {
        if (!open) return Optional.empty();
        return Optional.ofNullable(inbound.poll());
    }

    @Override
    public void close() {
        open = false;
    }

    @Override
    public boolean isOpen() {
        return open;
    }
}
