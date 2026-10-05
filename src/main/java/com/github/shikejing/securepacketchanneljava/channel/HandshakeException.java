package com.github.shikejing.securepacketchanneljava.channel;

/**
 * 密钥协商/恢复失败。携带 {@link HandshakeFailure} 原因，
 * 与报文完整性失败（接收路径上的 RejectReason.INTEGRITY_FAILURE）完全区分。
 * 异常信息不包含任何密钥材料。
 */
public final class HandshakeException extends Exception {
    private final HandshakeFailure reason;

    public HandshakeException(HandshakeFailure reason, String detail) {
        super("handshake failed: " + reason + (detail == null ? "" : " (" + detail + ")"));
        this.reason = reason;
    }

    public HandshakeFailure reason() {
        return reason;
    }
}
