package com.example.progassign2;

public enum Packet {
    HELLO_SERVER(0),
    WELCOME(1),
    REQ_CA_CERT(2),
    SERVER_CERT(3),
    FILE_NAME(4),
    FILE_BLOCK(5),
    END(6),
    NONCE(7),
    AES_CP2_ENCRYPT(8),
    CP2_ENCRYPTED_FILE(9);

    public int value;

    Packet(int i) {
        this.value = i;
    }

    public int getValue() {
        return value;
    }
}
