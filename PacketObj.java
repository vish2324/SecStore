package com.example.progassign2;

import java.io.Serializable;

class PacketObj implements Serializable{
    private Packet type;
    private int length;
    private byte[] message;

    PacketObj(Packet type, int length, byte[] message) {
        this.type = type;
        this.length = length;
        this.message = message;
    }

    Packet getType() {
        return type;
    }

    int getLength() {
        return length;
    }

    byte[] getMessage() {
        return message;
    }
}