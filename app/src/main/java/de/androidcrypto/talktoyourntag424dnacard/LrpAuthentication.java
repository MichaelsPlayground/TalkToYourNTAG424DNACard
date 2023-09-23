package de.androidcrypto.talktoyourntag424dnacard;

import static de.androidcrypto.talktoyourntag424dnacard.Utils.divideArrayToList;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.hexStringToByteArray;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.printData;

import android.nfc.tech.IsoDep;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.androidcrypto.talktoyourntag424dnacard.ShamirSharingSecret.Scheme;

import de.androidcrypto.talktoyourntag424dnacard.lrp.CMAC;

/**
 * This class is running all LRP authentication commands
 * It is based on the document provided by NXP:
 * AN12304 Leakage Resilient Primitive (LRP) Specification
 */

public class LrpAuthentication {

    private final String TAG = LrpAuthentication.class.getName();
    private IsoDep isodep;

    public LrpAuthentication(IsoDep isodep) {
        this.isodep = isodep;
    }

    public void runAllTests() {
        Log.d(TAG, "runAllTests");
        boolean success;

        // init the library
        // is done in test_lricb_enc and test_lricb_dec

        if (test_incr_counter(false)) {
            Log.d(TAG, "test_incr_counter PASSED");
        } else {
            Log.e(TAG, "test_incr_counter FAILURE");
        }
        ;

        if (test_vectors_generate_plaintexts(false)) {
            Log.d(TAG, "test_vectors_generate_plaintexts PASSED");
        } else {
            Log.e(TAG, "test_vectors_generate_plaintexts FAILURE");
        }
        ;

        if (test_vectors_updated_keys(false)) {
            Log.d(TAG, "test_vectors_updated_keys PASSED");
        } else {
            Log.e(TAG, "test_vectors_updated_keys FAILURE");
        }
        ;

        byte[] paddingTest = Utils.hexStringToByteArray("1234567890ab8000");
        byte[] depaddedTest = removePadding(paddingTest);
        Log.d(TAG, printData("paddingTest ", paddingTest));
        Log.d(TAG, printData("depaddedTest", depaddedTest));

        if (test_lricb_enc(false)) {
            Log.d(TAG, "test_lricb_enc PASSED");
        } else {
            Log.e(TAG, "test_lricb_enc FAILURE");
        }
        ;

        if (test_lricb_dec(false)) {
            Log.d(TAG, "test_lricb_dec PASSED");
        } else {
            Log.e(TAG, "test_lricb_dec FAILURE");
        };

        if (test_cmac(true)) {
            Log.d(TAG, "test_cmac PASSED");
        } else {
            Log.e(TAG, "test_cmac FAILURE");
        };
    }

    private boolean test_incr_counter(boolean verbose) {
        if (verbose) Log.d(TAG, "test_incr_counter");
        boolean result;
        // testdata
        byte[] x00 = new byte[]{(byte) 0x00};
        byte[] x01 = new byte[]{(byte) 0x01};
        byte[] x02 = new byte[]{(byte) 0x02};
        byte[] xff = new byte[]{(byte) 0xFF};
        byte[] x1211 = new byte[]{(byte) 0x12, (byte) 0x11};
        byte[] x1212 = new byte[]{(byte) 0x12, (byte) 0x12};
        byte[] x0000 = new byte[]{(byte) 0x00, (byte) 0x00};
        byte[] x0001 = new byte[]{(byte) 0x00, (byte) 0x01};
        byte[] x0002 = new byte[]{(byte) 0x00, (byte) 0x02};
        byte[] xffff = new byte[]{(byte) 0xff, (byte) 0xff};
        byte[] x00000000 = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        byte[] xffffffff = new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        // tests
        byte[] data = incr_counter(x00);
        if (!compareTestValues(data, x01, "x00", verbose)) return false;
        data = incr_counter(x01);
        if (!compareTestValues(data, x02, "x01", verbose)) return false;
        data = incr_counter(xff);
        if (!compareTestValues(data, x00, "xff", verbose)) return false;
        data = incr_counter(x1211);
        if (!compareTestValues(data, x1212, "x1211", verbose)) return false;
        data = incr_counter(xffff);
        if (!compareTestValues(data, x0000, "xffff", verbose)) return false;
        data = incr_counter(x0000);
        if (!compareTestValues(data, x0001, "x0000", verbose)) return false;
        data = incr_counter(x0001);
        if (!compareTestValues(data, x0002, "x0001", verbose)) return false;
        data = incr_counter(xffffffff);
        if (!compareTestValues(data, x00000000, "xffffffff", verbose)) return false;
        return true;
    }

    private boolean test_vectors_generate_plaintexts(boolean verbose) {
        if (verbose) Log.d(TAG, "test_vectors_generate_plaintexts");
        // testdata see LRP Spec pages 10 ff
        byte[] key = Utils.hexStringToByteArray("567826B8DA8E768432A9548DBE4AA3A0");
        byte[] pt00 = Utils.hexStringToByteArray("ac20d39f5341fe98dfca21da86ba7914");
        byte[] pt01 = Utils.hexStringToByteArray("907da03d672449166915e4563e089d6d");
        byte[] pt02 = Utils.hexStringToByteArray("92faa8b878ccd50c6313db59099dcce8");
        byte[] pt03 = Utils.hexStringToByteArray("372fa13dd43efd419859dcbcfceffbf8");
        byte[] pt04 = Utils.hexStringToByteArray("5fe2e468958b6b05c8a034f33823cf1b");
        byte[] pt05 = Utils.hexStringToByteArray("ab75e2fa6dccbaa04e85d07fb94eed28");
        byte[] pt06 = Utils.hexStringToByteArray("ac05bcdac44b14bffdf8907498695389");
        byte[] pt07 = Utils.hexStringToByteArray("0af975ed752942d756a8a97c78c09cd8");
        byte[] pt08 = Utils.hexStringToByteArray("4f58afb57cad5fe16c033f9df5b5b3fe");
        byte[] pt09 = Utils.hexStringToByteArray("5698d7b5f5956614d57b5a18b9b8810e");
        byte[] pt10 = Utils.hexStringToByteArray("5ac8cfba77f7c6a61348afb92b1195ca");
        byte[] pt11 = Utils.hexStringToByteArray("012d66108916e29a86e88146a1047d3a");
        byte[] pt12 = Utils.hexStringToByteArray("25f8f92546dba865119146fc9b260bca");
        byte[] pt13 = Utils.hexStringToByteArray("be9ee44fc42d8c73c65e2b6d0b2454eb");
        byte[] pt14 = Utils.hexStringToByteArray("37d734a51c076eb803bd530e17eb87dc");
        byte[] pt15 = Utils.hexStringToByteArray("71b444af257a93215311d758dd333247");
        byte[][] p = generate_plaintexts(key);
        if (!compareTestValues(p[0], pt00, "pt00", verbose)) return false;
        if (!compareTestValues(p[1], pt01, "pt01", verbose)) return false;
        if (!compareTestValues(p[2], pt02, "pt02", verbose)) return false;
        if (!compareTestValues(p[3], pt03, "pt03", verbose)) return false;
        if (!compareTestValues(p[4], pt04, "pt04", verbose)) return false;
        if (!compareTestValues(p[5], pt05, "pt05", verbose)) return false;
        if (!compareTestValues(p[6], pt06, "pt06", verbose)) return false;
        if (!compareTestValues(p[7], pt07, "pt07", verbose)) return false;
        if (!compareTestValues(p[8], pt08, "pt08", verbose)) return false;
        if (!compareTestValues(p[9], pt09, "pt09", verbose)) return false;
        if (!compareTestValues(p[10], pt10, "pt10", verbose)) return false;
        if (!compareTestValues(p[11], pt11, "pt11", verbose)) return false;
        if (!compareTestValues(p[12], pt12, "pt12", verbose)) return false;
        if (!compareTestValues(p[13], pt13, "pt13", verbose)) return false;
        if (!compareTestValues(p[14], pt14, "pt14", verbose)) return false;
        if (!compareTestValues(p[15], pt15, "pt15", verbose)) return false;
        return true;
    }

    private boolean test_vectors_updated_keys(boolean verbose) {
        if (verbose) Log.d(TAG, "test_vectors_updated_keys");
        // testdata see LRP Spec pages 10 ff
        byte[] key = Utils.hexStringToByteArray("567826B8DA8E768432A9548DBE4AA3A0");
        byte[] uk00 = Utils.hexStringToByteArray("163d14ed24ed935373568ec521e96cf4");
        byte[] uk01 = Utils.hexStringToByteArray("1c519c000208b95a39a65db058327188");
        byte[] uk02 = Utils.hexStringToByteArray("fe30ab50467e61783bfe6b5e0560160e");
        byte[] uk03 = Utils.hexStringToByteArray("1d5c31d1632b6f2b2d5fa66c436913a5");
        byte[][] uk = generate_updated_keys(key);
        if (!compareTestValues(uk[0], uk00, "uk00", verbose)) return false;
        if (!compareTestValues(uk[1], uk01, "uk01", verbose)) return false;
        if (!compareTestValues(uk[2], uk02, "uk02", verbose)) return false;
        if (!compareTestValues(uk[3], uk03, "uk03", verbose)) return false;
        return true;
    }

    private boolean test_lricb_enc(boolean verbose) {
        if (verbose) Log.d(TAG, "test_lricb_enc");
        byte[] key = Utils.hexStringToByteArray("E0C4935FF0C254CD2CEF8FDDC32460CF");
        byte[] pt = Utils.hexStringToByteArray("012D7F1653CAF6503C6AB0C1010E8CB0");
        byte[] ctExp = Utils.hexStringToByteArray("FCBBACAA4F29182464F99DE41085266F480E863E487BAAF687B43ED1ECE0D623");
        byte[] counter = Utils.hexStringToByteArray("C3315DBF");
        boolean initSuccess = _init(key, 0, counter, true, true);

        Log.d(TAG, printData("counter", counter));
        Log.d(TAG, printData("this.r ", this.r));
        byte[] increasedCounter = incr_counter(this.r);
        Log.d(TAG, printData("this.rI", increasedCounter));


        if (verbose) Log.d(TAG, "init library success");
        //String lrp = LRP(key, 0, counter, true); // true = pad
        byte[] ct = encrypt(pt, verbose);
        if (!compareTestValues(ct, ctExp, "ct", verbose)) return false;
        return true;
    }

    private boolean test_lricb_dec(boolean verbose) {
        if (verbose) Log.d(TAG, "test_lricb_dec");
        byte[] key = Utils.hexStringToByteArray("E0C4935FF0C254CD2CEF8FDDC32460CF");
        byte[] ct = Utils.hexStringToByteArray("FCBBACAA4F29182464F99DE41085266F480E863E487BAAF687B43ED1ECE0D623");
        byte[] ptExp = Utils.hexStringToByteArray("012D7F1653CAF6503C6AB0C1010E8CB0");
        byte[] counter = Utils.hexStringToByteArray("C3315DBF");
        boolean initSuccess = _init(key, 0, counter, true, true);
        if (verbose) Log.d(TAG, "init library success");
        //String lrp = LRP(key, 0, counter, true); // true = pad
        byte[] pt = decrypt(ct, verbose);
        if (!compareTestValues(pt, ptExp, "pt", verbose)) return false;
        return true;
    }

    private boolean test_cmac(boolean verbose) {
        if (verbose) Log.d(TAG, "test_cmac");
        byte[] key1 = Utils.hexStringToByteArray("8195088CE6C393708EBBE6C7914ECB0B");
        byte[] input1 = Utils.hexStringToByteArray("BBD5B85772C7");
        byte[] cmacExp1 = Utils.hexStringToByteArray("AD8595E0B49C5C0DB18E77355F5AAFF6");
        byte[] key2 = Utils.hexStringToByteArray("E2F84A0B0AF40EFEB3EEA215A436605C");
        byte[] input2 = Utils.hexStringToByteArray("8BF1DDA9FE445560A4F4EB9CE0");
        byte[] cmacExp2 = Utils.hexStringToByteArray("D04382DF71BC293FEC4BB10BDB13805F");
        byte[] key3 = Utils.hexStringToByteArray("5AA9F6C6DE5138113DF5D6B6C77D5D52");
        byte[] input3 = Utils.hexStringToByteArray("A4434D740C2CB665FE5396959189383F");
        byte[] cmacExp3 = Utils.hexStringToByteArray("8B43ADF767E46B692E8F24E837CB5EFC");

        boolean initSuccess = _init(key1, 0, new byte[16], true, true); // todo check on counter 16 byte length
        if (verbose) Log.d(TAG, "init library success");
        byte[] cmac1 = cmac(input1, verbose);
        if (!compareTestValues(cmac1, cmacExp1, "cmac1", verbose)) {
            Log.d(TAG, "1 FAILURE");
            return false;
        }

        initSuccess = _init(key2, 0, new byte[16], true, true); // todo check on counter 16 byte length
        if (verbose) Log.d(TAG, "init library success");
        byte[] cmac2 = cmac(input2, verbose);
        if (!compareTestValues(cmac2, cmacExp2, "cmac2", verbose)) {
            Log.d(TAG, "1 FAILURE");
            //return false;
        }

        initSuccess = _init(key3, 0, new byte[16], true, true); // todo check on counter 16 byte length
        if (verbose) Log.d(TAG, "init library success");
        byte[] cmac3 = cmac(input3, verbose);
        if (!compareTestValues(cmac3, cmacExp3, "cmac3", verbose)) {
            Log.d(TAG, "1 FAILURE");
            //return false;
        }

        return true;
    }


    // vars
    private byte[] key; // param key: secret key from which updated keys will be derived
    private int u; // param u: number of updated key to use (counting from 0)
    private byte[] r; // param r: IV/counter value (default: all zeros)
    private boolean pad; // param pad: whether to use bit padding or no (default: true)
    private byte[][] p;
    private byte[][] ku;
    private byte[] kp;

    private final int AES_BLOCK_SIZE = 16;

    private boolean _init(byte[] key, int u, byte[] r, boolean pad, boolean verbose) {
        /*
        Leakage Resilient Primitive
        param key: secret key from which updated keys will be derived
        param u: number of updated key to use (counting from 0)
        param r: IV/counter value (default: all zeros)
        param pad: whether to use bit padding or no (default: true)
         */
        if (verbose) {
            Log.d(TAG, "_init library with " + Utils.printData("key", key) +
                    " u: " + u + printData(" r", r) + " pad: " + pad);
        }
        if (r == null) {
            this.r = new byte[16];
        } else {
            this.r = r;
        }
        this.key = key;
        this.u = u;
        this.pad = pad;
        this.p = generate_plaintexts(this.key);
        this.ku = generate_updated_keys(this.key);
        this.kp = this.ku[this.u];
        return true;
    }

    private byte[] incr_counter(byte[] bytes) {
        int length = bytes.length;
        // fill missing bytes
        byte[] bytesFull = new byte[4];
        if (length == 1) {
            System.arraycopy(bytes, 0, bytesFull, 3, length);
        } else if (length == 2) {
            System.arraycopy(bytes, 0, bytesFull, 2, length);
        } else if (length == 3) {
            System.arraycopy(bytes, 0, bytesFull, 1, length);
        } else if (length == 4) {
            bytesFull = bytes.clone();
        }

        int value = ByteBuffer.wrap(bytesFull).getInt();
        /*
        Log.e(TAG, "incr_counter " + printData("bytes    ", bytes));
        Log.e(TAG, "incr_counter " + printData("bytesFull", bytesFull));
        Log.e(TAG, "incr_counter value: " + value);
        */
        final byte[] xffffffff = new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        if (Arrays.equals(bytes, xffffffff)) {
            // overflow
            value = 0;
        } else {
            value++;
        }
        //Log.e(TAG, "incr_counter valueN:" + value);
        byte[] bytesFullIncreased = ByteBuffer.allocate(4).putInt(value).array();
        //Log.e(TAG, "incr_counter " + printData("bytesFullIncreased", bytesFullIncreased));
        if (length == 1) {
            if (value == 256) {
                // overflow
                return new byte[1];
            }
            return Arrays.copyOfRange(bytesFullIncreased, 3, 4);
        }
        if (length == 2) {
            if (value == 65536) {
                // overflow
                return new byte[2];
            }
            return Arrays.copyOfRange(bytesFullIncreased, 2, 4);
        }
        if (length == 3) {
            if (value == 16777216) {
                // overflow
                return new byte[3];
            }
            return Arrays.copyOfRange(bytesFullIncreased, 1, 4);
        }

        return bytesFullIncreased;
        // returns big endian
    }

    private byte[][] generate_plaintexts(byte[] key) {
        return generate_plaintexts(key, 4, false);
    }

    private byte[][] generate_plaintexts(byte[] key, boolean verbose) {
        return generate_plaintexts(key, 4, verbose);
    }

    private byte[][] generate_plaintexts(byte[] key, int m, boolean verbose) {
        // this is Algorithm 1
        if (verbose)
            Log.d(TAG, "generate_plaintexts for key " + Utils.bytesToHexNpeUpperCase(key) + " and m: " + m);
        final byte[] data0x55 = hexStringToByteArray("55555555555555555555555555555555");
        final byte[] data0xaa = hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        final byte[] iv = new byte[16];
        byte[] keyRounds = key.clone();
        int m2Pow = (int) Math.pow(2, m);
        byte[][] p = new byte[m2Pow][];
        // length doubling
        keyRounds = AES.encrypt(iv, keyRounds, data0x55, verbose);
        for (int i = 0; i < m2Pow; i++) {
            p[i] = AES.encrypt(iv, keyRounds, data0xaa, verbose);
            keyRounds = AES.encrypt(iv, keyRounds, data0x55, verbose);
        }
        return p;
    }

    private byte[][] generate_updated_keys(byte[] key) {
        return generate_updated_keys(key, 4, false);
    }

    private byte[][] generate_updated_keys(byte[] key, boolean verbose) {
        return generate_updated_keys(key, 4, verbose);
    }

    private byte[][] generate_updated_keys(byte[] key, int q, boolean verbose) {
        // this is Algorithm 2
        if (verbose)
            Log.d(TAG, "generate_updated_keys for key " + Utils.bytesToHexNpeUpperCase(key) + " and q: " + q);
        final byte[] data0x55 = hexStringToByteArray("55555555555555555555555555555555");
        final byte[] data0xaa = hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        final byte[] iv = new byte[16];
        byte[] keyRounds = key.clone();
        int m2Pow = (int) Math.pow(2, q);
        byte[][] uk = new byte[m2Pow][];
        // length doubling
        keyRounds = AES.encrypt(iv, keyRounds, data0xaa, verbose);
        for (int i = 0; i < m2Pow; i++) {
            uk[i] = AES.encrypt(iv, keyRounds, data0xaa, verbose);
            keyRounds = AES.encrypt(iv, keyRounds, data0x55, verbose);
        }
        return uk;
    }

    private byte[] encrypt(byte[] data, boolean verbose) {
        /**
         * LRICB encrypt and update counter (LRICBEnc)
         * param data: plaintext
         * return: ciphertext
         */
        if (verbose) Log.d(TAG, "encrypt " + printData("data", data));
        if (data == null) {
            if (verbose) Log.e(TAG, "encrypt: data is null, aborted");
            return null;
        }
        if ((!isMultiple(data.length, 16)) && (this.pad == false)) {
            if (verbose)
                Log.e(TAG, "encrypt: data length is not a multiple of AES block size (16)");
            return null;
        }

        ByteArrayOutputStream baosPt = new ByteArrayOutputStream();
        baosPt.write(data, 0, data.length);
        if (this.pad == true) {
            baosPt.write((byte) 0x80); // padding
            while (!isMultiple(baosPt.size(), 16)) {
                baosPt.write((byte) 0x00);
            }
        }
        byte[] ptStream = baosPt.toByteArray();
        if (verbose) Log.d(TAG, printData("ptStream", ptStream));
        List<byte[]> blockS = Utils.divideArrayToList(ptStream, 16);
        ByteArrayOutputStream baosCt = new ByteArrayOutputStream();
        for (int i = 0; i < blockS.size(); i++) {
            byte[] y = eval_lrp(this.p, this.kp, this.r, true, verbose);
            byte[] block = blockS.get(i);
            byte[] ct = e(y, block);
            baosCt.write(ct, 0, ct.length);
            this.r = incr_counter(this.r);
        }
        byte[] ciphertext = baosCt.toByteArray();
        if (verbose) Log.d(TAG, printData("ciphertext", ciphertext));
        return ciphertext;
    }

    private byte[] decrypt(byte[] data, boolean verbose) {
        /**
         * LRICB decrypt and update counter (LRICBDecs)
         * param data: ciphertext
         * return: plaintext
         */
        if (verbose) Log.d(TAG, "decrypt " + printData("data", data));
        if (data == null) {
            if (verbose) Log.e(TAG, "decrypt: data is null, aborted");
            return null;
        }
        if (!isMultiple(data.length, 16)) {
            if (verbose)
                Log.e(TAG, "decrypt: data length is not a multiple of AES block size (16)");
            return null;
        }

        if (verbose) Log.d(TAG, printData("ctStream", data));
        List<byte[]> blockS = Utils.divideArrayToList(data, 16);
        ByteArrayOutputStream baosPt = new ByteArrayOutputStream();
        for (int i = 0; i < blockS.size(); i++) {
            byte[] y = eval_lrp(this.p, this.kp, this.r, true, verbose);
            byte[] block = blockS.get(i);
            byte[] pt = d(y, block);
            baosPt.write(pt, 0, pt.length);
            this.r = incr_counter(this.r);
        }
        byte[] plaintext = baosPt.toByteArray();
        // remove a padding
        if (this.pad) {
            // remove padding
            plaintext = removePadding(plaintext);
        }
        if (verbose) Log.d(TAG, printData("plaintext", plaintext));
        return plaintext;
    }

    private byte[] eval_lrp(byte[][] p, byte[] kp, byte[] x, boolean isFinal, boolean verbose) {
        if (verbose)
            Log.d(TAG, "eval_lrp with p[][] " + printData("kp", kp) + printData(" x", x) + " isFinal: " + isFinal);
        // Algorithm 3 assuming m = 4
        byte[] y = kp.clone();
        List<Integer> nibbleList = Utils.getNibblesFromByteArray(x);
        if (verbose) Log.d(TAG, "nibbleList size: " + nibbleList.size());
        for (int i = 0; i < nibbleList.size(); i++) {
            byte[] p_j = p[nibbleList.get(i)];
            if (verbose) Log.d(TAG, "i: " + i + printData(" p_j", p_j));
            y = e(y, p_j);
            if (verbose) Log.d(TAG, "i: " + i + printData(" y", y));
        }
        if (isFinal) {
            y = e(y, new byte[16]);
            if (verbose) Log.d(TAG, "isFinal: " + printData(" y", y));
        }
        return y;
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

    private byte[] d(byte[] key, byte[] ciphertext) {
        // simple AES ECB decryption
        // todo check data length
        byte[] plainText = null;
        try {
            SecretKey sks = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, sks);
            plainText = cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException e) {
            Log.e(TAG, "d Exception: " + e.getMessage());
            return null;
        }
        return plainText;
    }

    private byte[] cmac(byte[] data, boolean verbose) {
        /**
         * Calculate CMAC_LRP
         * Algorithm: 6
         * param data: message to be authenticated
         * return: CMAC result
         */
        // todo check data multiple of 16
        if ((data == null) || (data.length < 1)) {
            Log.e(TAG, "cmac: data is NULL or of length 0, aborted");
            return null;
        }
        List<byte[]> blockS = Utils.divideArrayToList(data, 16);

        byte[] k0 = eval_lrp(this.p, this.kp, new byte[16], true, verbose);
        Log.e(TAG, printData("=== k0 ===", k0));

        // return this value:
        byte[] generatedCmac;

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(k0, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            //MessageDigest md = CMAC.newHash(cipher);
            generatedCmac = CMAC.sum(data, cipher, 16);
            /*
            CMAC cmac = new CMAC();
            cmac.newHash(cipher);
            generatedCmac = cmac.sum(data, cipher, 16);

             */
        } catch (Exception e) {
            throw new RuntimeException(e);
        }



        /*
        try {
            CMAC cmac = new CMAC(k0);
            cmac.update(data);
            generatedCmac = cmac.doFinal();
            Log.e(TAG, printData("=== kF ===", generatedCmac));
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "lrp.CMAC Exception: " + e.getMessage());

            return null;
        }

         */

        //generatedCmac = eval_lrp(this.p, this.kp, generatedCmac, true, verbose);

        if (verbose) return generatedCmac;

        byte[] k1 = multiplyValues(k0, 2);
        byte[] k2 = multiplyValues(k0, 4);
        Log.e(TAG, printData("=== k1 ===", k1));
        Log.e(TAG, printData("=== k2 ===", k2));

        byte[] y = new byte[16];
        byte[] xLast = new byte[0];
        for (int i = 0; i < blockS.size(); i++) {
            byte[] x = blockS.get(i);
            xLast = x.clone();
            y = xor(x, y);
            y = eval_lrp(this.p, this.kp, y, true, verbose);
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        boolean isPadded = false;
        if (xLast.length < AES_BLOCK_SIZE) {
            isPadded = true;
            baos.write((byte) 0x80); // padding
            while (!isMultiple(baos.size(), AES_BLOCK_SIZE)) {
                baos.write((byte) 0x00);
            }
        }
        byte[] xLastPadded = baos.toByteArray();
        Log.d(TAG, printData("xLastPadded", xLastPadded));



        y = xor(xLastPadded, y);



        Shamir shamir = new Shamir();
        Shamir.Element element = new Shamir.Element(k0);
        Log.d(TAG, "element: " + element.toString());
        long l2 = 2;

        //Log.d(TAG, element(l2).encode);


        //LrpCmac cm = new LrpCmac()
// K0 = evalLRP(m, {{p0, . . . , p2m−1}, k0
//}, l, 0
//n
//, f inal)
//K1 = K0 · x mod x
//128 + x
//7 + x
//2 + x + 1
//K2 = K0 · x
//2 mod x
//128 + x
//7 + x
//2 + x + 1
        // K1 = K0 · x mod x exp128 + xexp7 + xexp2 + x + 1

/*
k0:  b'8b4895c68ceca596a6d27fd0e5690c52'
k1:  b'16912b8d19d94b2d4da4ffa1cad21823'
k1ElementK0:  b'8b4895c68ceca596a6d27fd0e5690c52'
k1Element2:  b'00000000000000000000000000000002'
k2Element4:  b'00000000000000000000000000000004'
k2:  b'2d22571a33b2965a9b49ff4395a43046'
k0:  b'5a10f23f7171ebaaf7d1cf461a90bb49'
k1:  b'b421e47ee2e3d755efa39e8c35217692'
k1ElementK0:  b'5a10f23f7171ebaaf7d1cf461a90bb49'
k1Element2:  b'00000000000000000000000000000002'
k2Element4:  b'00000000000000000000000000000004'
k2:  b'6843c8fdc5c7aeabdf473d186a42eda3'
k0:  b'957075e9bb5e6a513d8e6a0369218e3f'
k1:  b'2ae0ebd376bcd4a27b1cd406d2431cf9'
k1ElementK0:  b'957075e9bb5e6a513d8e6a0369218e3f'
k1Element2:  b'00000000000000000000000000000002'
k2Element4:  b'00000000000000000000000000000004'
k2:  b'55c1d7a6ed79a944f639a80da48639f2'

 */


        if (isPadded) {
            y = xor(y, k2);
        } else {
            y = xor(y, k1);
        }
        byte[] result = eval_lrp(this.p, this.kp, y, true, verbose);
        if (verbose) Log.d(TAG, "cmac " + printData("cmac", result));
        return result;
    }

    public byte[] Cmac(byte[] key, byte[] msg) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            CmacGo cmac = new CmacGo(secretKeySpec, 16); // Assuming that 'this' is an instance of CMAC class
            cmac.update(msg, 0, msg.length);
            return cmac.doFinal();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null; // Handle the error as needed
        }
    }

    public static byte[] multiplyValues(byte[] array, int multiplier) {
        byte[] newArray = new byte[array.length];
        for (int i = 0; i < array.length; i++) {
            newArray[i] = (byte) (array[i] * multiplier);
        }
        return newArray;
    }

    /**
     * see scheme in Mifare DESFire Light Features and Hints AN12343.pdf page 38
     * @return
     */
    private byte[] calculateDiverseKeyLrp(byte[] key, byte[][] p) {
        // todo sanity checks
        byte[] loopIv = new byte[16];
        byte[] ciphertext = new byte[0];
        for (int i = 0; i < 16; i++) {
            byte[] plaintext = p[i].clone();
            ciphertext = AES.encrypt(loopIv, key, plaintext);
            loopIv = ciphertext.clone();
        }
        return ciphertext;
    }

    // e.g. value 5, base 2 result is false, value 6, base 2 result is true
    private boolean isMultiple(int value, int base) {
        if (value % base == 0) {
            return true;
        } else {
            return false;
        }
    }

    private byte[] removePadding(byte[] paddedData) {
        // the padding in 0x80 .. 0x00..0x00...
        // to remove we check from the end if there is an 0x80 in the byte array and remove from that position to the end
        if ((paddedData == null) || (paddedData.length < 1)) {
            return null;
        }
        int paddedDataLength = paddedData.length;
        byte paddingByte = (byte) 0x80;
        int paddingPosition = paddedDataLength;
        for (int i = 0; i < paddedDataLength; i++) {
            byte paddedDataByte = paddedData[(paddedDataLength - 1) - i];
            if (paddedDataByte == paddingByte) {
                paddingPosition = (paddedDataLength - 1) - i;
                break;
            }
        }
        return Arrays.copyOf(paddedData, paddingPosition);
    }

    private byte[] xor(byte[] dataA, byte[] dataB) {
        return xor(dataA, dataB, false);
    }

    private byte[] xor(byte[] dataA, byte[] dataB, boolean verbose) {
        if (verbose) Log.d(TAG, "xor" + printData("dataA", dataA) + printData(" dataB", dataB));
        if ((dataA == null) || (dataB == null)) {
            Log.e(TAG, "xor - dataA or dataB is NULL, aborted");
            return null;
        }
        // sanity check - both arrays need to be of the same length
        int dataALength = dataA.length;
        int dataBLength = dataB.length;
        if (dataALength != dataBLength) {
            Log.e(TAG, "xor - dataA and dataB lengths are different, aborted (dataA: " + dataALength + " dataB: " + dataBLength + " bytes)");
            return null;
        }
        for (int i = 0; i < dataALength; i++) {
            dataA[i] ^= dataB[i];
        }
        return dataA;
    }

    /**
     * section for test helper
     */

    private boolean compareTestValues(byte[] real, byte[] expected, String valueName, boolean verbose) {
        if (Arrays.equals(real, expected)) {
            if (verbose) Log.d(TAG, "valueName: " + valueName + " EQUALS");
            return true;
        } else {
            if (verbose) Log.d(TAG, "valueName: " + valueName + " NOT EQUALS");
            if (verbose) Log.d(TAG, printData(valueName + " R", real));
            if (verbose) Log.d(TAG, printData(valueName + " E", expected));
            return false;
        }
    }

}
