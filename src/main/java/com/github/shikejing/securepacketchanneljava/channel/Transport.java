package com.github.shikejing.securepacketchanneljava.channel;

import java.util.Optional;

/**
 * 本地字节传输抽象：进程内回环或内存管道。不依赖任何外部服务。
 */
public interface Transport extends AutoCloseable {
    /** 发送一段字节。对端关闭后写入被丢弃。 */
    void send(byte[] bytes);

    /** 取走一段字节；无数据时返回 empty。 */
    Optional<byte[]> poll();

    /** 关闭本端；对端读取到关闭后返回 empty。 */
    @Override
    void close();

    boolean isOpen();
}
