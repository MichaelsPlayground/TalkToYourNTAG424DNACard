package de.androidcrypto.talktoyourntag424dnacard.lrp;

import static de.androidcrypto.talktoyourntag424dnacard.lrp.Constants.blocksize;
import static de.androidcrypto.talktoyourntag424dnacard.lrp.Constants.zeroBlock;
import static de.androidcrypto.talktoyourntag424dnacard.lrp.Util.encryptWith;

import java.util.Arrays;

public class LrpCipher {

    private LrpMultiCipher Multi;
    private byte[] Key;
    private long Counter;
    //private int CounterSize;
    private int CounterSize = 0; // fixed value
/*
In the implementation of LRP, the counter has a specific size: 4 bytes.
The LRP standard seems to indicate that the size of the counter for LRP is just based on
how many bits you need. In any case, if you set CounterSize on the LrpCipher to 4,
you will get the behavior in the chip, and if you leave it you will get the behavior in the document.
 */
    private boolean Encrypting;


    public LrpCipher(LrpMultiCipher Multi, byte[] Key, long Counter, boolean Encrypting) {
        this.Multi = Multi;
        this.Key = Key;
        this.Counter = Counter;
        this.Encrypting = Encrypting;
    }

    public LrpCipher(LrpMultiCipher Multi, byte[] Key, long Counter, int CounterSize, boolean Encrypting) {
        this.Multi = Multi;
        this.Key = Key;
        this.Counter = Counter;
        this.CounterSize = CounterSize;
        this.Encrypting = Encrypting;
    }



    public LrpCipher decrypter() {
        LrpCipher newCipher = new LrpCipher(this.Multi, this.Key, this.Counter, this.CounterSize, false);
        return newCipher;
    }

    public LrpCipher encrypter() {
        LrpCipher newCipher = new LrpCipher(this.Multi, this.Key, this.Counter, this.CounterSize, true);
        return newCipher;
    }

    public int blockSize() {
        return blocksize;
    }

    public byte[] evalLRP(int[] x, boolean finalValue) {
        int l = x.length;

        byte[] y = this.Key;
        for (int i = 0; i < l; i++) {
            //int p = this.Multi.P[x[i]];
            byte[] p = this.Multi.P.get(x[i]);
            y = encryptWith(y, p);
        }
        if (finalValue) {
            y = encryptWith(y, zeroBlock);
        }
        return y;
    }

    public void encryptBlocks(byte[] dst, byte[] src) {
        int srcblocks = src.length / blocksize;
        int numblocks = dst.length / blocksize;
        if (srcblocks < numblocks) {
            numblocks = srcblocks;
        }
        for (int i = 0; i < numblocks; i++) {
            int blockstart = i * blocksize;
            byte[] b = Arrays.copyOfRange(src, blockstart, blockstart + blocksize);
            byte[] encryptedBlock = encryptWith(b, this.Key);
            System.arraycopy(encryptedBlock, 0, dst, blockstart, blocksize);
        }
    }

    public byte[] getKey() {
        return Key;
    }
}
