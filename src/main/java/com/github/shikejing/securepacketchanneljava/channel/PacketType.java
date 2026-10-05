package com.github.shikejing.securepacketchanneljava.channel;

/** Frame types on the wire. Control frames live in their own sequence space. */
public enum PacketType {
    DATA(0),
    HELLO(1),
    HELLO2(2),
    FIN(3),
    ROTATE(4),
    ROTATE_ACK(5),
    CLOSE(6);

    private final int code;

    PacketType(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static PacketType fromCode(int code) {
        for (PacketType t : values()) {
            if (t.code == code) {
                return t;
            }
        }
        return null;
    }
}
