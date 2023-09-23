package de.androidcrypto.talktoyourntag424dnacard;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CmacGo {
    // source (Golang): https://github.com/johnnyb/gocrypto
    private static final byte p64 = 0x1b;
    private static final byte p128 = (byte) 0x87;
    private static final byte p256 = 0x25;
    private static final byte p512 = 0x25;
    private static final byte p1024 = 0x43;

    private static final String AES_ALGORITHM = "AES";

    private SecretKey k0;
    private SecretKey k1;
    private byte[] buf;
    private int off;
    private int tagsize;

    public CmacGo(SecretKey key, int tagsize) throws NoSuchAlgorithmException {
        int blocksize = key.getEncoded().length;
        this.k0 = new SecretKeySpec(key.getEncoded(), AES_ALGORITHM);
        this.k1 = new SecretKeySpec(shift(key.getEncoded()), AES_ALGORITHM);
        this.buf = new byte[blocksize];
        this.off = 0;
        this.tagsize = tagsize;
    }

    public static byte[] shift(byte[] input) {
        byte[] result = new byte[input.length];
        byte b = 0;
        for (int i = input.length - 1; i >= 0; i--) {
            byte bit = (byte) (input[i] >> 7);
            result[i] = (byte) ((input[i] << 1) | b);
            b = bit;
        }
        return result;
    }

    public void update(byte[] msg, int offset, int length) {
        int bs = k0.getEncoded().length;
        int n = length;

        if (off > 0) {
            int dif = bs - off;
            if (n > dif) {
                for (int i = 0; i < dif; i++) {
                    buf[off + i] ^= msg[offset + i];
                }
                offset += dif;
                n -= dif;
                encrypt(buf);
                off = 0;
            } else {
                for (int i = 0; i < n; i++) {
                    buf[off + i] ^= msg[offset + i];
                }
                off += n;
                return;
            }
        }

        if (n > bs) {
            int nn = length & (~(bs - 1));
            if (length == nn) {
                nn -= bs;
            }
            for (int i = 0; i < nn; i += bs) {
                for (int j = 0; j < bs; j++) {
                    buf[j] ^= msg[offset + i + j];
                }
                encrypt(buf);
            }
            offset += nn;
            n -= nn;
        }

        if (n > 0) {
            for (int i = 0; i < n; i++) {
                buf[off + i] ^= msg[offset + i];
            }
            off += n;
        }
    }

    public byte[] doFinal() {
        int blocksize = k0.getEncoded().length;

        byte[] hash = new byte[blocksize];

        if (off < blocksize) {
            hash = k1.getEncoded();
        } else {
            hash = k0.getEncoded();
        }

        for (int i = 0; i < blocksize; i++) {
            hash[i] ^= buf[i];
        }

        if (off < blocksize) {
            hash[off] ^= (byte) 0x80;
        }

        encrypt(hash);

        return Arrays.copyOfRange(hash, 0, tagsize);
    }

    private void encrypt(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, k0);
            cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static CmacGo NewWithTagSize(byte[] keyBytes, int tagSize) throws NoSuchAlgorithmException {
        if (tagSize <= 0 || tagSize > 16) {
            throw new IllegalArgumentException("Invalid tag size");
        }
        SecretKey key = new SecretKeySpec(keyBytes, AES_ALGORITHM);
        CmacGo cmac = new CmacGo(key,tagSize);
        //cmac.TAG_SIZE = tagSize;
        return cmac;
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] keyBytes = new byte[16]; // 128-bit key
        SecretKey key = new SecretKeySpec(keyBytes, AES_ALGORITHM);
        int tagSize = 16; // 128-bit tag size

        CmacGo cmac = new CmacGo(key, tagSize);

        byte[] message = "Hello, CMAC!".getBytes();

        cmac.update(message, 0, message.length);
        byte[] mac = cmac.doFinal();

        System.out.println("CMAC Tag: " + bytesToHex(mac));
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}

