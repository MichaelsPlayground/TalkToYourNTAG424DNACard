package de.androidcrypto.talktoyourntag424dnacard.lrp;

import android.util.Log;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import de.androidcrypto.talktoyourntag424dnacard.Utils;

public class CMAC {

    private final static String TAG = "lrp CMAC";

    private static final byte p64 = (byte)0x1b;
    private static final byte p128 = (byte)0x87;
    private static final byte p256 = (byte)0x425;
    private static final byte p512 = (byte)0x125;
    private static final byte p1024 = (byte)0x43;

    private static final String errUnsupportedCipher = "cipher block size not supported";
    private static final String errInvalidTagSize = "tags size must between 1 and the cipher's block size";

    public static byte[] sum(byte[] msg, Cipher c, int tagsize) throws Exception {
        Log.d(TAG, "sum " + Utils.printData("msg", msg) + " tagSize " + tagsize);
        //AlgorithmParameters algParameters = c.getParameters();
        //byte[] algParametersEncoded = algParameters.getEncoded();
        //Log.d(TAG, Utils.printData("algParametersEncoded", algParametersEncoded));
        MessageDigest h = newWithTagSize(c, tagsize);
        h.update(msg);
        return h.digest();
    }

    public static boolean verify(byte[] mac, byte[] msg, Cipher c, int tagsize) throws Exception {
        byte[] sum = sum(msg, c, tagsize);
        return Arrays.equals(mac, sum);
    }

    public static MessageDigest newHash(Cipher c) throws Exception {
        return newWithTagSize(c, c.getBlockSize());
    }

    public static MessageDigest newWithTagSize(Cipher c, int tagsize) throws Exception {
        int blocksize = c.getBlockSize();

        if (tagsize <= 0 || tagsize > blocksize) {
            throw new Exception(errInvalidTagSize);
        }

        byte[] k0 = new byte[blocksize];
        byte[] k1 = new byte[blocksize];
        byte[] buf = new byte[blocksize];

        //c.doFinal(k0, 0);
        k0 = c.doFinal(k0);
        Log.d(TAG, Utils.printData("A k0", k0));
        shift(k0, k0);
        Log.d(TAG, Utils.printData("B k0", k0));
        k0[blocksize - 1] ^= (byte) (p64 & 0xFF);

        shift(k1, k0);
        k1[blocksize - 1] ^= (byte) (p64 & 0xFF);
        Log.d(TAG, "before calling new MacFunc");
        Log.d(TAG, Utils.printData("k0", k0));
        Log.d(TAG, Utils.printData("k1", k1));
        return new MacFunc(c, k0, k1, buf, tagsize);
    }

    private static void shift(byte[] dest, byte[] src) {
        int carry = 0;
        for (int i = 0; i < dest.length; i++) {
            int b = src[i] & 0xFF;
            dest[i] = (byte) ((b << 1) | carry);
            carry = (b >>> 7) & 1;
        }
    }

    private static class MacFunc extends MessageDigest {

        private final Cipher cipher;
        private final byte[] k0;
        private final byte[] k1;
        private final byte[] buf;
        private int off;
        private final int tagsize;

        protected MacFunc(Cipher cipher, byte[] k0, byte[] k1, byte[] buf, int tagsize) {
            super("CMAC");
            this.cipher = cipher;
            this.k0 = k0;
            this.k1 = k1;
            this.buf = buf;
            this.off = 0;
            this.tagsize = tagsize;
        }

        @Override
        protected void engineUpdate(byte input) {
            buf[off++] = input;
            if (off == buf.length) {
                cipher.update(buf, 0, buf.length);
                off = 0;
            }
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int len) {
            Log.d(TAG, "engineUpdate " + Utils.printData("input", input) + " offset: " + offset + " len: " + len);
            while (len > 0) {
                int n = Math.min(len, buf.length - off);
                System.arraycopy(input, offset, buf, off, n);
                off += n;
                offset += n;
                len -= n;
                if (off == buf.length) {
                    cipher.update(buf, 0, buf.length);
                    off = 0;
                }
            }
            Log.d(TAG, "engineUpdate completed");
        }

        @Override
        protected byte[] engineDigest() {
            Log.d(TAG, "engineDigest tagSize: " + tagsize);
            Log.d(TAG, Utils.printData("k0", k0));
            Log.d(TAG, Utils.printData("k1", k1));
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] result = new byte[tagsize];
            byte[] ct;
            if (off == 0) {
                //ct = cipher.update(k1, 0, k1.length);
                ct = cipher.update(k1);
                baos.write(ct, 0, ct.length);
            } else {
                //ct = cipher.update(k0, 0, k0.length);
                ct = cipher.update(k0);
                baos.write(ct, 0, ct.length);
                //ct = cipher.update(k1, 0, k1.length);
                ct = cipher.update(k1);
                baos.write(ct, 0, ct.length);
            }
            try {
                //cipher.doFinal(result, 0);
                ct = cipher.doFinal();
                baos.write(ct, 0, ct.length);
            } catch (BadPaddingException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            }
            result = baos.toByteArray();
            Log.d(TAG, Utils.printData("result", result));
            return Arrays.copyOf(result, tagsize);
            //return result;
        }

        @Override
        protected void engineReset() {
            off = 0;
            Arrays.fill(buf, (byte) 0);
        }
    }
}

class Main {
    /**
     * Shifts the elements of the source byte array to the left by 1 bit and stores the result in the destination byte array.
     * The most significant bit of each element is stored in the least significant bit of the next element.
     * The least significant bit of the last element is stored in the return value.
     *
     * @param dst the destination byte array
     * @param src the source byte array
     * @return the least significant bit of the last element of the source byte array
     */
    public static int shift(byte[] dst, byte[] src) {
        byte b = 0;
        byte bit;
        for (int i = src.length - 1; i >= 0; i--) {
            bit = (byte) (src[i] >> 7);
            dst[i] = (byte) ((src[i] << 1) | b);
            b = bit;
        }
        return b;
    }

    public static void main(String[] args) {
        // Test the shift method
        /*
        byte[] src = {0b11001010, 0b10100101, 0b01011010};
        byte[] dst = new byte[src.length];
        int result = shift(dst, src);
        System.out.println("Result: " + result);
        System.out.println("Destination array: " + Arrays.toString(dst));

         */
    }
}
