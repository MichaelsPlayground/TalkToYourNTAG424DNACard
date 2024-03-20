package de.androidcrypto.talktoyourntag424dnacard.lrppy;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class LRP {
    // code from https://github.com/lucianox777/nfc-ev2-crypto
    private byte[] key;
    private int u;
    private byte[] r;
    private boolean pad;
    private List<byte[]> p;
    private List<byte[]> ku;
    private byte[] kp;

    public LRP(byte[] key, int u, byte[] r, boolean pad) throws Exception {
        if (r == null) {
            r = new byte[16];
        }
        this.key = key;
        this.u = u;
        this.r = r;
        this.pad = pad;

        this.p = generatePlaintexts(key);
        this.ku = generateUpdatedKeys(key);
        this.kp = this.ku.get(u);
    }

    private static byte[] removePad(byte[] pt) {
        int padLength = 0;

        for (int i = pt.length - 1; i >= 0; i--) {
            padLength++;

            if (pt[i] == (byte) 0x80) {
                break;
            }

            if (pt[i] != 0x00) {
                throw new RuntimeException("Invalid padding");
            }
        }

        byte[] result = new byte[pt.length - padLength];
        System.arraycopy(pt, 0, result, 0, pt.length - padLength);
        return result;
    }

    private static byte[] incrCounter(byte[] r) {
        int maxBitLength = r.length * 8;

        long ctrOrig = byteArrayToLong(r);
        long ctrIncr = ctrOrig + 1;

        if (Long.bitCount(ctrIncr) > maxBitLength) {
            // Overflow, reset counter to zero
            return new byte[r.length];
        }

        return longToByteArray(ctrIncr, r.length);
    }

    private static long byteArrayToLong(byte[] bytes) {
        long value = 0;
        for (int i = 0; i < bytes.length; i++) {
            value = (value << 8) | (bytes[i] & 0xff);
        }
        return value;
    }

    private static byte[] longToByteArray(long value, int length) {
        byte[] result = new byte[length];
        for (int i = length - 1; i >= 0; i--) {
            result[i] = (byte) (value & 0xff);
            value >>= 8;
        }
        return result;
    }

    private static byte[] e(byte[] k, byte[] v) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(k, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(v);
    }

    private static byte[] d(byte[] k, byte[] v) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(k, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(v);
    }

    private static List<byte[]> generatePlaintexts(byte[] k) throws Exception {
        List<byte[]> p = new ArrayList<>();
        byte[] h = k.clone();
        h = e(h, "55555555555555555555555555555555".getBytes(StandardCharsets.UTF_8));
        for (int i = 0; i < Math.pow(2, 4); i++) {
            p.add(e(h, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8)));
            h = e(h, "55555555555555555555555555555555".getBytes(StandardCharsets.UTF_8));
        }
        return p;
    }

    private static List<byte[]> generateUpdatedKeys(byte[] k) throws Exception {
        List<byte[]> uk = new ArrayList<>();
        byte[] h = k.clone();
        h = e(h, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8));
        for (int i = 0; i < 4; i++) {
            uk.add(e(h, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8)));
            h = e(h, "55555555555555555555555555555555".getBytes(StandardCharsets.UTF_8));
        }
        return uk;
    }

    private static byte[] evalLrp(List<byte[]> p, byte[] kp, byte[] x, boolean finalRound) throws Exception {
        byte[] y = kp.clone();
        for (byte b : x) {
            int x_i = b & 0xFF; // Convert byte to unsigned int
            y = e(y, p.get(x_i));
        }
        if (finalRound) {
            y = e(y, new byte[16]);
        }
        return y;
    }

    public byte[] encrypt(byte[] data) throws Exception {
        ByteArrayOutputStream ptStream = new ByteArrayOutputStream();
        ByteArrayOutputStream ctStream = new ByteArrayOutputStream();
        ptStream.write(data);

        if (pad) {
            ptStream.write(0x80);
            while (ptStream.size() % 16 != 0) {
                ptStream.write(0x00);
            }
        } else if (ptStream.size() % 16 != 0) {
            throw new RuntimeException("Parameter pt must have length multiple of AES block size.");
        } else if (ptStream.size() == 0) {
            throw new RuntimeException("Zero length pt not supported.");
        }

        ByteArrayInputStream inputStream = new ByteArrayInputStream(ptStream.toByteArray());

        while (true) {
            byte[] block = new byte[16];
            int bytesRead = inputStream.read(block);
            if (bytesRead == -1) {
                break;
            }
            byte[] y = evalLrp(p, kp, r, true);
            ctStream.write(e(y, block));
            r = incrCounter(r);
        }

        return ctStream.toByteArray();
    }

    public byte[] decrypt(byte[] data) throws Exception {
        ByteArrayOutputStream ptStream = new ByteArrayOutputStream();
        ByteArrayInputStream ctStream = new ByteArrayInputStream(data);

        while (true) {
            byte[] block = new byte[16];
            int bytesRead = ctStream.read(block);
            if (bytesRead == -1) {
                break;
            }
            byte[] y = evalLrp(p, kp, r, true);
            ptStream.write(d(y, block));
            r = incrCounter(r);
        }

        byte[] pt = ptStream.toByteArray();

        if (pad) {
            pt = removePad(pt);
        }

        return pt;
    }

    public byte[] cmac(byte[] data) throws Exception {
        ByteArrayInputStream stream = new ByteArrayInputStream(data);
        byte[] k0 = evalLrp(p, kp, new byte[16], true);
        byte[] k1 = e(k0, e(k0, new byte[16]));
        byte[] k2 = e(k0, e(k0, e(k0, e(k0, new byte[16]))));
        byte[] y = new byte[16];

        while (true) {
            byte[] x = new byte[16];
            int bytesRead = stream.read(x);

            if (bytesRead < 0 || bytesRead < 16 || stream.available() == 0) {
                break;
            }

            for (int i = 0; i < 16; i++) {
                y[i] ^= x[i];
            }
            y = evalLrp(p, kp, y, true);
        }

        int padBytes = 0;
        byte[] x = new byte[16];

        if (stream.available() == 0) {
            padBytes = 16 - x.length;
            x = Arrays.copyOf(x, x.length + 1);
            x[x.length - 1] = (byte) 0x80;

            while (padBytes > 1) {
                padBytes--;
                x = Arrays.copyOf(x, x.length + 1);
                x[x.length - 1] = 0x00;
            }
        }

        for (int i = 0; i < 16; i++) {
            y[i] ^= x[i];
        }

        if (padBytes == 0) {
            for (int i = 0; i < 16; i++) {
                y[i] ^= k1[i];
            }
        } else {
            for (int i = 0; i < 16; i++) {
                y[i] ^= k2[i];
            }
        }

        return evalLrp(p, kp, y, true);
    }

    public byte[] cmacOrg(byte[] data) throws Exception {
        ByteArrayInputStream stream = new ByteArrayInputStream(data);
        byte[] k0 = evalLrp(p, kp, new byte[16], true);
        byte[] k1 = e(k0, e(k0, new byte[16]));
        byte[] k2 = e(k0, e(k0, e(k0, e(k0, new byte[16]))));
        byte[] y = new byte[16];

        while (true) {
            byte[] x = new byte[16];
            int bytesRead = stream.read(x);

            if (bytesRead < 0 || bytesRead < 16 || stream.available() == 0) {
                break;
            }

            for (int i = 0; i < 16; i++) {
                y[i] ^= x[i];
            }
            y = evalLrp(p, kp, y, true);
        }

        int padBytes = 0;
        byte[] x = new byte[16];

        if (stream.available() == 0) {
            padBytes = 16 - x.length;
            x = Arrays.copyOf(x, x.length + 1);
            x[x.length - 1] = (byte) 0x80;

            while (padBytes > 1) {
                padBytes--;
                x = Arrays.copyOf(x, x.length + 1);
                x[x.length - 1] = 0x00;
            }
        }

        for (int i = 0; i < 16; i++) {
            y[i] ^= x[i];
        }

        if (padBytes == 0) {
            for (int i = 0; i < 16; i++) {
                y[i] ^= k1[i];
            }
        } else {
            for (int i = 0; i < 16; i++) {
                y[i] ^= k2[i];
            }
        }

        return evalLrp(p, kp, y, true);
    }

}



