package de.androidcrypto.talktoyourntag424dnacard;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

public class LrpCmac {

    private static final int p64 = 0x1b;
    private static final int p128 = 0x87;
    private static final int p256 = 0x425;
    private static final int p512 = 0x125;
    private static final int p1024 = 0x80043;

    private static final int errUnsupportedCipher = -1;
    private static final int errInvalidTagSize = -2;

    public static byte[] sum(byte[] msg, byte[] key, int tagsize) throws NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        return sum(msg, secretKeySpec, tagsize);
    }

    public static byte[] sum(byte[] msg, SecretKeySpec key, int tagsize) throws NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (Exception e) {
            throw new NoSuchAlgorithmException("Cipher initialization error");
        }

        byte[] k0 = new byte[key.getEncoded().length];
        byte[] k1 = new byte[key.getEncoded().length];
        byte[] buf = new byte[key.getEncoded().length];
        Arrays.fill(k0, (byte) 0);
        Arrays.fill(k1, (byte) 0);
        Arrays.fill(buf, (byte) 0);

        int blocksize = key.getEncoded().length;
        if (tagsize <= 0 || tagsize > blocksize) {
            throw new InvalidKeyException("Invalid tag size");
        }

        int p;
        switch (blocksize) {
            default:
                throw new NoSuchAlgorithmException("Unsupported cipher");
            case 8:
                p = p64;
                break;
            case 16:
                p = p128;
                break;
            case 32:
                p = p256;
                break;
            case 64:
                p = p512;
                break;
            case 128:
                p = p1024;
                break;
        }

        System.arraycopy(key.getEncoded(), 0, k0, 0, key.getEncoded().length);
        xor(k0, k0);

        int v = shift(k0, k0);
        k0[blocksize - 1] ^= (byte) (v == 1 ? p : 0);

        v = shift(k1, k0);
        k1[blocksize - 1] ^= (byte) (v == 1 ? p : 0);

        // Compute CMAC
        byte[] sum = new byte[blocksize];
        int off = 0;

        int bs = blocksize;
        int n = msg.length;

        if (off > 0) {
            int dif = bs - off;
            if (n > dif) {
                xor(buf, 0, msg, 0, dif);
                cipher.update(buf, 0, blocksize, buf, 0);
                off = 0;
                System.arraycopy(buf, 0, sum, 0, bs);
                Arrays.fill(buf, (byte) 0);
            } else {
                xor(buf, 0, msg, 0, n);
                off += n;
                System.arraycopy(buf, 0, sum, 0, bs);
                Arrays.fill(buf, (byte) 0);
                return sum;
            }
        }

        if (n > bs) {
            int nn = n & (~(bs - 1));
            if (n == nn) {
                nn -= bs;
            }
            for (int i = 0; i < nn; i += bs) {
                xor(buf, 0, msg, i, i + bs);
                cipher.update(buf, 0, blocksize, buf, 0);
            }
            System.arraycopy(buf, 0, sum, 0, bs);
            Arrays.fill(buf, (byte) 0);
            msg = Arrays.copyOfRange(msg, nn, msg.length);
        }

        if (n > 0) {
            xor(buf, 0, msg, 0, msg.length);
            off += msg.length;
            System.arraycopy(buf, 0, sum, 0, bs);
        }

        if (off < bs) {
            sum[off] ^= (byte) 0x80;
        }

        cipher.update(sum, 0, blocksize, sum, 0);

        byte[] result = new byte[tagsize];
        System.arraycopy(sum, 0, result, 0, tagsize);
        return result;
    }

    private static void xor(byte[] dest, byte[] src) {
        xor(dest, 0, src, 0, src.length);
    }

    private static void xor(byte[] dest, int destOffset, byte[] src, int srcOffset, int srcEnd) {
        for (int i = srcOffset; i < srcEnd; i++) {
            dest[destOffset++] ^= src[i];
        }
    }

    private static int shift(byte[] dst, byte[] src) {
        byte b = 0;
        for (int i = src.length - 1; i >= 0; i--) {
            byte bit = (byte) (src[i] >> 7);
            dst[i] = (byte) ((src[i] << 1) | b);
            b = bit;
        }
        return b;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        byte[] msg = "Hello, World!".getBytes();
        int tagsize = 16;

        byte[] mac = sum(msg, key, tagsize);

        System.out.println("MAC: " + bytesToHex(mac));
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}

