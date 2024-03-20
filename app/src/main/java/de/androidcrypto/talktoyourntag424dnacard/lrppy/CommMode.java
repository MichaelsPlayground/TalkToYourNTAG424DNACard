package de.androidcrypto.talktoyourntag424dnacard.lrppy;

public enum CommMode {
    PLAIN(1),
    MAC(2),
    FULL(3);

    private final int value;

    CommMode(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
