package de.androidcrypto.talktoyourntag424dnacard.lrp;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class MacFunc {
    private Cipher cipher;
    private byte[] buf;
    private int off;
    private byte[] k0;
    private byte[] k1;
    private int tagsize;

    public MacFunc(Cipher cipher, byte[] k0, byte[] k1, int tagsize) {
        this.cipher = cipher;
        this.buf = new byte[cipher.getBlockSize()];
        this.off = 0;
        this.k0 = k0;
        this.k1 = k1;
        this.tagsize = tagsize;
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

        if (off > 0) {
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
        int blocksize = cipher.getBlockSize();

        byte[] hash = new byte[blocksize];

        if (off < blocksize) {
            System.arraycopy(k1, 0, hash, 0, k1.length);
        } else {
            System.arraycopy(k0, 0, hash, 0, k0.length);
        }

        xor(hash, 0, buf, 0, buf.length);
        if (off < blocksize) {
            hash[off] ^= 0x80;
        }

        //cipher.Encrypt(hash, hash);
        hash = encrypt(cipher, hash);
        byte[] result = new byte[b.length + tagsize];
        System.arraycopy(b, 0, result, 0, b.length);
        System.arraycopy(hash, 0, result, b.length, tagsize);
        return result;
    }

    private void xor(byte[] dest, int destOffset, byte[] src, int srcOffset, int length) {
        for (int i = 0; i < length; i++) {
            dest[destOffset + i] ^= src[srcOffset + i];
        }
    }

    public byte[] encrypt(Cipher cipher, byte[] data) {
        try {
            return cipher.doFinal(data);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }
    }
}
