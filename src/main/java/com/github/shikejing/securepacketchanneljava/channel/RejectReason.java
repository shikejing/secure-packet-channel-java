package com.github.shikejing.securepacketchanneljava.channel;

/**
 * 报文被拒绝时的可区分原因类别。
 */
public enum RejectReason {
    /** 会话尚未完成密钥协商 */
    SESSION_NOT_ESTABLISHED,
    /** 会话已关闭 */
    SESSION_CLOSED,
    /** 报文属于已被重连取代的旧会话代 */
    STALE_GENERATION,
    /** 报文使用已被轮换淘汰的旧密钥代 */
    STALE_EPOCH,
    /** 完整性校验失败（报文被篡改或密钥不匹配） */
    INTEGRITY_FAILURE,
    /** 序号超出重放窗口上界（来自过远的未来） */
    SEQUENCE_AHEAD_OF_WINDOW,
    /** 序号落在窗口之下（过老，可能是重放） */
    SEQUENCE_TOO_OLD,
    /** 序号在窗口内但已被接收过（确定的重放） */
    DUPLICATE,
    /** 报文格式非法，无法解析 */
    MALFORMED,
    /** 在途缓冲已满 */
    BUFFER_FULL
}
