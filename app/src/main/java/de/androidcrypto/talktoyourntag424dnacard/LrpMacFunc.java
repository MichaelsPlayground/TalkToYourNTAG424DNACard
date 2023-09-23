package de.androidcrypto.talktoyourntag424dnacard;

import android.util.Log;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class LrpMacFunc {
    private final static String TAG = "LrpMacFunc";
    private Cipher cipher;
    private byte[] buf;
    private int off;
    private byte[] k0;
    private byte[] k1;
    private int tagsize;
    private static final byte p64 = (byte)0x1b;
    private static final String errInvalidTagSize = "tags size must between 1 and the cipher's block size";

    public LrpMacFunc(Cipher cipher, byte[] k0, byte[] k1, byte[] buf, int tagsize) {
        Log.d(TAG, "init MacFund with k0/1/buf");
        Log.d(TAG, Utils.printData("k0", k0));
        Log.d(TAG, Utils.printData("k1", k1));
        Log.d(TAG, Utils.printData("buf", buf));
        Log.d(TAG, "tagSize: " + tagsize);
        this.cipher = cipher;
        this.buf = buf;
        this.off = 0;
        this.k0 = k0;
        this.k1 = k1;
        this.tagsize = tagsize;
    }

    public LrpMacFunc(Cipher cipher, int tagsize) throws Exception {
        Log.d(TAG, "init MacFund with Cipher");
        this.cipher = cipher;
        int blocksize = cipher.getBlockSize();

        if (tagsize <= 0 || tagsize > blocksize) {
            throw new Exception(errInvalidTagSize);
        }

        byte[] k0 = new byte[blocksize];
        byte[] k1 = new byte[blocksize];
        byte[] buf = new byte[blocksize];
        Log.d(TAG, Utils.printData("  k0", k0));
        k0 = cipher.doFinal(k0);
        Log.d(TAG, Utils.printData("A k0", k0));
        shift(k0, k0);
        Log.d(TAG, Utils.printData("B k0", k0));
        k0[blocksize - 1] ^= (byte) (p64 & 0xFF);

        shift(k1, k0);
        k1[blocksize - 1] ^= (byte) (p64 & 0xFF);
        Log.d(TAG, "before calling new MacFunc");
        Log.d(TAG, Utils.printData("k0", k0));
        Log.d(TAG, Utils.printData("k1", k1));
        buf = new byte[tagsize];

        this.cipher = cipher;
        this.buf = buf;
        this.off = 0;
        this.k0 = k0;
        this.k1 = k1;
        this.tagsize = tagsize;

        //new LrpMacFunc(cipher, k0, k1, buf, tagsize);
    }

    public LrpMacFunc(byte[] key, int tagsize) throws Exception {
        Log.d(TAG, "init MacFund with key");
        Log.d(TAG, Utils.printData("key", key) + " tagSize: " + 16);
        Cipher cipher = null;
        try {
            Log.d(TAG, "1 start cipher");
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        } catch (Exception e) {
            Log.e(TAG, "Exception: " + e.getMessage());
            return;
        }

        this.cipher = cipher;
        int blocksize = cipher.getBlockSize();

        if (tagsize <= 0 || tagsize > blocksize) {
            throw new Exception(errInvalidTagSize);
        }

        byte[] k0 = new byte[blocksize];
        byte[] k1 = new byte[blocksize];
        byte[] buf = new byte[blocksize];
        Log.d(TAG, Utils.printData("  k0", k0));
        //k0 = cipher.doFinal(k0);
        k0 = e(key, k0);
        Log.d(TAG, Utils.printData("A k0", k0));
        // found:   c41e9782c89d2a650b8447e1190c1b88
        // expected 8b4895c68ceca596a6d27fd0e5690c52
        shift(k0, k0);
        Log.d(TAG, Utils.printData("B k0", k0));
        k0[blocksize - 1] ^= (byte) (p64 & 0xFF);

        shift(k1, k0);
        k1[blocksize - 1] ^= (byte) (p64 & 0xFF);
        Log.d(TAG, "before calling new MacFunc");
        Log.d(TAG, Utils.printData("k0", k0));
        Log.d(TAG, Utils.printData("k1", k1));
        buf = new byte[tagsize];

        this.cipher = cipher;
        this.buf = buf;
        this.off = 0;
        this.k0 = k0;
        this.k1 = k1;
        this.tagsize = tagsize;

        //new LrpMacFunc(cipher, k0, k1, buf, tagsize);
    }

    private void shift(byte[] dest, byte[] src) {
        int carry = 0;
        for (int i = 0; i < dest.length; i++) {
            int b = src[i] & 0xFF;
            dest[i] = (byte) ((b << 1) | carry);
            carry = (b >>> 7) & 1;
        }
    }

    public int Size() {
        return cipher.getBlockSize();
    }

    public int BlockSize() {
        return cipher.getBlockSize();
    }

    public void Reset() {
        for (int i = 0; i < buf.length; i++) {
            buf[i] = 0;
        }
        off = 0;
    }

    public int Write(byte[] msg) {
        int bs = BlockSize();
        int n = msg.length;

        Log.d(TAG, "Write " + Utils.printData("msg", msg) + " bs: " + bs + " n: " + n);
        Log.d(TAG, "Write " + Utils.printData("k0", k0) + Utils.printData(" k1", k1));
        if (off > 0) {
            Log.d(TAG, "off > 0");
            int dif = bs - off;
            if (n > dif) {
                xor(buf, off, msg, 0, dif);
                msg = Arrays.copyOfRange(msg, dif, msg.length);
                //cipher.Encrypt(buf, buf);
                buf = encrypt(cipher, buf);
                off = 0;
            } else {
                xor(buf, off, msg, 0, n);
                off += n;
                return n;
            }
        }
        Log.d(TAG, "off !> 0");
        buf = new byte[msg.length];
        if (msg.length > bs) {
            int length = msg.length;
            int nn = length & (~(bs - 1));
            if (length == nn) {
                nn -= bs;
            }
            for (int i = 0; i < nn; i += bs) {
                xor(buf, 0, msg, i, i + bs);
                //cipher.Encrypt(buf, buf);
                buf = encrypt(cipher, buf);
            }
            msg = Arrays.copyOfRange(msg, nn, msg.length);
        }

        if (msg.length > 0) {
            xor(buf, off, msg, 0, msg.length);
            off += msg.length;
        }

        return n;
    }

    public byte[] Sum(byte[] b) {
        Log.d(TAG, "Sum " + Utils.printData("b", b));
        int blocksize = cipher.getBlockSize();

        byte[] hash = new byte[blocksize];

        if (off < blocksize) {
            Log.d(TAG, "off < blocksize " + Utils.printData("k1", k1));
            System.arraycopy(k1, 0, hash, 0, k1.length);
        } else {
            Log.d(TAG, "off !< blocksize " + Utils.printData("k0", k0));
            System.arraycopy(k0, 0, hash, 0, k0.length);
        }

        xor(hash, 0, buf, 0, buf.length);
        if (off < blocksize) {
            hash[off] ^= 0x80;
            Log.d(TAG, "off < blocksize ");
        }

        //cipher.Encrypt(hash, hash);
        Log.d(TAG, "Sum before last encrypt " + Utils.printData("hash", hash));
        hash = encrypt(cipher, hash);
        Log.d(TAG, "Sum after  last encrypt " + Utils.printData("hash", hash));
        byte[] result = new byte[b.length + tagsize];
        System.arraycopy(b, 0, result, 0, b.length);
        System.arraycopy(hash, 0, result, b.length, tagsize);
        return result;
    }

    private void xor(byte[] dest, int destOffset, byte[] src, int srcOffset, int length) {
        Log.d(TAG, "xor " + Utils.printData("dest", dest) + Utils.printData(" src", src));
        Log.d(TAG, "xor destOffset: " + destOffset + " srcOffset: " + srcOffset + " length: " + length);
        for (int i = 0; i < length; i++) {
            dest[destOffset + i] ^= src[srcOffset + i];
        }
    }

    public byte[] encrypt(Cipher cipher, byte[] data) {
        try {
            return cipher.doFinal(data);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] e(byte[] key, byte[] data) {
        // simple AES ECB encryption
        // todo check data length
        byte[] cipherText = null;
        try {
            SecretKey sks = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, sks);
            cipherText = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException e) {
            Log.e(TAG, "e Exception: " + e.getMessage());
            return null;
        }
        return cipherText;
    }
}
