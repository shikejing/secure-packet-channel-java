package com.github.shikejing.securepacketchanneljava.tests;

import com.github.shikejing.securepacketchanneljava.channel.Transport;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * 测试用传输层包装：记录所有发出的字节，可选择截留（不转发），
 * 便于用例篡改、重放、乱序注入报文。
 */
final class InterceptingTransport implements Transport {
    private final Transport delegate;
    private final List<byte[]> sent = new ArrayList<>();
    private boolean forwarding = true;

    InterceptingTransport(Transport delegate) {
        this.delegate = delegate;
    }

    @Override
    public synchronized void send(byte[] bytes) {
        sent.add(bytes);
        if (forwarding) {
            delegate.send(bytes);
        }
    }

    @Override
    public Optional<byte[]> poll() {
        return delegate.poll();
    }

    @Override
    public void close() {
        delegate.close();
    }

    @Override
    public boolean isOpen() {
        return delegate.isOpen();
    }

    /** 截留后续报文：只记录不转发。 */
    synchronized void stopForwarding() {
        forwarding = false;
    }

    synchronized void resumeForwarding() {
        forwarding = true;
    }

    synchronized List<byte[]> sent() {
        return new ArrayList<>(sent);
    }

    synchronized byte[] lastSent() {
        return sent.get(sent.size() - 1);
    }

    synchronized void clearSent() {
        sent.clear();
    }

    /** 把记录过的字节原样（或篡改后）注入对端。 */
    void injectRaw(byte[] bytes) {
        delegate.send(bytes);
    }
}
