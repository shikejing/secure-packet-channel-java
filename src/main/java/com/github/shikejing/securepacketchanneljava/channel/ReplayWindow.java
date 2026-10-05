package com.github.shikejing.securepacketchanneljava.channel;

/**
 * 滑动重放窗口。语义确定：
 * <ul>
 *   <li>seq &gt; highest：窗口前移，接受（前提是已通过完整性校验）。</li>
 *   <li>seq &lt;= highest - windowSize：过老，拒绝（SEQUENCE_TOO_OLD）。</li>
 *   <li>窗口内未见过：接受并标记。</li>
 *   <li>窗口内已见过：拒绝（DUPLICATE）。</li>
 * </ul>
 * 判定与标记分离：先 {@link #classify} 判定，完整性校验通过后再 {@link #mark}，
 * 被篡改的报文不会污染窗口状态。
 */
public final class ReplayWindow {
    private final int size;
    private long highest = -1;
    private long bitmap = 0; // bit i 表示 highest - i 是否已接收（i < 64）

    public ReplayWindow(int size) {
        if (size < 1 || size > ChannelConfig.MAX_WINDOW_SIZE) {
            throw new IllegalArgumentException("window size out of range: " + size);
        }
        this.size = size;
    }

    public enum Verdict { ACCEPT_NEW, ACCEPT_WITHIN_WINDOW, TOO_OLD, DUPLICATE }

    public synchronized Verdict classify(long seq) {
        if (seq < 0) return Verdict.TOO_OLD;
        if (seq > highest) return Verdict.ACCEPT_NEW;
        long offset = highest - seq;
        if (offset >= size) return Verdict.TOO_OLD;
        if (offset < Long.SIZE && ((bitmap >>> offset) & 1L) != 0) return Verdict.DUPLICATE;
        return Verdict.ACCEPT_WITHIN_WINDOW;
    }

    /** 标记 seq 已接收。只允许在完整性校验通过后调用。 */
    public synchronized void mark(long seq) {
        if (seq > highest) {
            long shift = seq - highest;
            if (shift >= Long.SIZE) {
                bitmap = 1L;
            } else {
                bitmap = (bitmap << shift) | 1L;
            }
            highest = seq;
        } else {
            long offset = highest - seq;
            if (offset < Long.SIZE) {
                bitmap |= (1L << offset);
            }
        }
    }

    public synchronized long highest() { return highest; }

    /** 窗口容量变更只影响后续判定。 */
    public synchronized ReplayWindow withSize(int newSize) {
        ReplayWindow w = new ReplayWindow(newSize);
        w.highest = this.highest;
        w.bitmap = this.bitmap;
        return w;
    }
}
