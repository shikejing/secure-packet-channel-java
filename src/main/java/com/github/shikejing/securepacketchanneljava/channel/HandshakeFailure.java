package com.github.shikejing.securepacketchanneljava.channel;

/**
 * 密钥协商失败原因，与报文完整性失败（RejectReason.INTEGRITY_FAILURE）完全区分。
 */
public enum HandshakeFailure {
    /** 对端 hello 无法解析 */
    MALFORMED_HELLO,
    /** 协议版本不兼容 */
    UNSUPPORTED_VERSION,
    /** 会话标识与预期不一致 */
    SESSION_MISMATCH,
    /** 重连恢复时序号状态非法（回退或跳变） */
    INVALID_RESUME_STATE,
    /** 协商在超时时间内未完成 */
    TIMEOUT
}
