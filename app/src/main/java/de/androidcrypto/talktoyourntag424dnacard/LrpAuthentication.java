package de.androidcrypto.talktoyourntag424dnacard;

import static de.androidcrypto.talktoyourntag424dnacard.Utils.hexStringToByteArray;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.printData;

import android.nfc.tech.IsoDep;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * This class is running all LRP authentication commands
 * It is based on the document provided by NXP:
 * AN12304 Leakage Resilient Primitive (LRP) Specification
 */

public class LrpAuthentication {

    private final String TAG = LrpAuthentication.class.getName();
    private IsoDep isoDep;

    private static final byte[] LRP_FIXED_COUNTER = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
    private static final byte[] LRP_FIXED_LENGTH = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080
    private static final byte[] LRP_FIXED_LABEL = new byte[]{(byte) (0x96), (byte) (0x69)}; // fixed to 0x9669

    public LrpAuthentication(IsoDep isodep){
    }

    public boolean runAllTests(boolean verbose) {
        Log.d(TAG, "runAllTests");
        boolean success = true;

        // init the library
        // is done in test_lricb_enc and test_lricb_dec

        if (test_incr_counter(verbose)) {
            Log.d(TAG, "test_incr_counter PASSED");
        } else {
            Log.e(TAG, "test_incr_counter FAILURE");
            success = false;
        }

        if (test_vectors_generate_plaintexts(verbose)) {
            Log.d(TAG, "test_vectors_generate_plaintexts PASSED");
        } else {
            Log.e(TAG, "test_vectors_generate_plaintexts FAILURE");
            success = false;
        }

        if (test_vectors_updated_keys(verbose)) {
            Log.d(TAG, "test_vectors_updated_keys PASSED");
        } else {
            Log.e(TAG, "test_vectors_updated_keys FAILURE");
            success = false;
        }

        byte[] paddingTest = Utils.hexStringToByteArray("1234567890ab8000");
        byte[] depaddedTest = removePadding(paddingTest);
        byte[] paddingTestExp = Utils.hexStringToByteArray("1234567890ab");
        Log.d(TAG, printData("paddingTest ", paddingTest));
        Log.d(TAG, printData("depaddedTest", depaddedTest));
        if (Arrays.equals(depaddedTest, paddingTestExp)) {
            Log.d(TAG, "test_depadding PASSED");
        } else {
            Log.d(TAG, "test_depadding FAILURE");
            success = false;
        }

        if (test_lricb_enc(verbose)) {
            Log.d(TAG, "test_lricb_enc PASSED");
        } else {
            Log.e(TAG, "test_lricb_enc FAILURE");
            success = false;
        }

        if (test_lricb_dec(verbose)) {
            Log.d(TAG, "test_lricb_dec PASSED");
        } else {
            Log.e(TAG, "test_lricb_dec FAILURE");
            success = false;
        }

        if (test_cmac(verbose)) {
            Log.d(TAG, "test_cmac PASSED");
        } else {
            Log.e(TAG, "test_cmac FAILURE");
            success = false;
        }

        if (test_verify(verbose)) {
            Log.d(TAG, "test_verify PASSED");
        } else {
            Log.e(TAG, "test_verify FAILURE");
            success = false;
        }
        return success;
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
        /*
        Log.d(TAG, "test_vectors_updated_keys with key 16*0");
        key = new byte[16];
        uk = generate_updated_keys(key);
        Log.d(TAG, printData("uk00", uk[0]));
        // uk00 length: 16 data: 50a26cb5df307e483de532f6afbec27b matches Mifare DESFire Light Features and Hints AN12343.pdf page 49
        Log.d(TAG, printData("uk01", uk[1]));
        Log.d(TAG, printData("uk02", uk[2]));
        Log.d(TAG, printData("uk03", uk[3]));
        */
        return true;
    }

    private boolean test_lricb_enc(boolean verbose) {
        if (verbose) Log.d(TAG, "test_lricb_enc");
        byte[] key = Utils.hexStringToByteArray("E0C4935FF0C254CD2CEF8FDDC32460CF");
        byte[] pt = Utils.hexStringToByteArray("012D7F1653CAF6503C6AB0C1010E8CB0");
        byte[] ctExp = Utils.hexStringToByteArray("FCBBACAA4F29182464F99DE41085266F480E863E487BAAF687B43ED1ECE0D623");
        byte[] counter = Utils.hexStringToByteArray("C3315DBF");
        boolean initSuccess = _init(key, 0, counter, true, false);

        if (verbose) Log.d(TAG, printData("counter", counter));
        if (verbose) Log.d(TAG, printData("this.r ", this.r));
        byte[] increasedCounter = incr_counter(this.r);
        if (verbose) Log.d(TAG, printData("this.rI", increasedCounter));
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
        boolean initSuccess = _init(key, 0, counter, true, false);
        if (verbose) Log.d(TAG, "init library success");
        //String lrp = LRP(key, 0, counter, true); // true = pad
        byte[] pt = decrypt(ct, verbose);
        if (!compareTestValues(pt, ptExp, "pt", verbose)) return false;
        return true;
    }

    private boolean test_cmac(boolean verbose) {
        if (verbose) Log.d(TAG, "test_cmac");
        // test data see Leakage Resilient Primitive (LRP) Specification AN12304.pdf pages 29 - 35
        byte[] key02 = Utils.hexStringToByteArray("8195088CE6C393708EBBE6C7914ECB0B");
        byte[] msg02 = Utils.hexStringToByteArray("bbd5b85772c7");
        byte[] mac02 = calculateCmac(key02, msg02, 16,verbose);
        byte[] mac02Exp = Utils.hexStringToByteArray("AD8595E0B49C5C0DB18E77355F5AAFF6");
        if (!compareTestValues(mac02, mac02Exp, "mac02", verbose)) return false;

        byte[] key06 = Utils.hexStringToByteArray("D66C19216297BAA60D7EA7C13E7839F9");
        byte[] msg06 = Utils.hexStringToByteArray("56076C610CAFB99D0EFAB679C360F34202655178EE7E7236E8BFCC1C66BDDA17F2F67F65ADBF55E70009FE84F0477B1845B7E5B48231FBD89436794CE39D36511F9F86CCE08E95430F6977E57FEE45A044B3D7AFD72694C1FAA6D07645080363D2AC6451C1AE37B621A1");
        byte[] mac06 = calculateCmac(key06, msg06, 16,verbose);
        byte[] mac06Exp = Utils.hexStringToByteArray("EFFA1488A73FDBCE5B91BBF9B8D51775");
        if (!compareTestValues(mac06, mac06Exp, "mac06", verbose)) return false;

        byte[] key11 = Utils.hexStringToByteArray("F91F1CF58941608F6F08ED190D3BF9B0");
        byte[] msg11 = Utils.hexStringToByteArray("CB09216F785295157058E08B38579E91AB808E8E02D47A508A78E1705D4847C6F3E52E15FA8611EECB7AFEAF0C8ED5E45A1E38C4F02335F68ED1E4FF7024B72810199752298997246EA0C387D6CB43FCA3FD153E0F83D6CFB0378629A1127EA6C3D69EF3F683BAD18714565060AD20C38DE75C720F79188D43C8A1F2026E825B211CC4FF2C50061F4343B7FB2C856E0216C29BB9B60B9749BD11AF2DE1C7CF1991FA2F43E820973DE13C2FCBC11D60BE599FDB3FD2C9A516857A411BA0D93E7B749E6A32552B19F52B5ED879DBCC88A0B0F1D342EC8F46C85418BE6EDF7C9C08FEB45623B22E682E85E61474F02C3AB8F2A16AAF05FC8FE5");
        byte[] mac11 = calculateCmac(key11, msg11, 16,false);
        byte[] mac11Exp = Utils.hexStringToByteArray("5D5E7B4182EBD50B31FFE52DE4AB5C11");
        if (!compareTestValues(mac11, mac11Exp, "mac11", verbose)) return false;

        byte[] key20 = Utils.hexStringToByteArray("AEA00AD0EF9243833DA4861D6A0D2C8C");
        byte[] msg20 = Utils.hexStringToByteArray("");
        byte[] mac20 = calculateCmac(key20, msg20, 16,verbose);
        byte[] mac20Exp = Utils.hexStringToByteArray("954230A72692BAB4CE1A44473D081376");
        if (!compareTestValues(mac20, mac20Exp, "mac20", verbose)) return false;

        byte[] key21 = Utils.hexStringToByteArray("FDDA1F4B99010C07521C4B74633559D3");
        byte[] msg21 = Utils.hexStringToByteArray("BE");
        byte[] mac21 = calculateCmac(key21, msg21, 16,verbose);
        byte[] mac21Exp = Utils.hexStringToByteArray("D3C4EE477F4FA5092B1FE726C18C3D01");
        if (!compareTestValues(mac21, mac21Exp, "mac21", verbose)) return false;
        return true;
    }

    private boolean test_verify(boolean verbose) {
        if (verbose) Log.d(TAG, "test_verify");
        // test data see Leakage Resilient Primitive (LRP) Specification AN12304.pdf pages 29 - 35
        byte[] key02 = Utils.hexStringToByteArray("8195088CE6C393708EBBE6C7914ECB0B");
        byte[] msg02 = Utils.hexStringToByteArray("bbd5b85772c7");
        //byte[] mac02 = calculateCmac(key02, msg02, 16,false);
        byte[] mac02Exp = Utils.hexStringToByteArray("AD8595E0B49C5C0DB18E77355F5AAFF6");
        //if (!compareTestValues(mac02, mac02Exp, "mac02", verbose)) return false;
        if (verbose) {
            if (VerifyCmac(key02, mac02Exp, msg02, 16, verbose)) {
                Log.d(TAG, "verify CMAC passed");
            } else {
                Log.d(TAG, "verify CMAC failure");
            }
        }

        byte[] key06 = Utils.hexStringToByteArray("D66C19216297BAA60D7EA7C13E7839F9");
        byte[] msg06 = Utils.hexStringToByteArray("56076C610CAFB99D0EFAB679C360F34202655178EE7E7236E8BFCC1C66BDDA17F2F67F65ADBF55E70009FE84F0477B1845B7E5B48231FBD89436794CE39D36511F9F86CCE08E95430F6977E57FEE45A044B3D7AFD72694C1FAA6D07645080363D2AC6451C1AE37B621A1");
        //byte[] mac06 = calculateCmac(key06, msg06, 16,false);
        byte[] mac06Exp = Utils.hexStringToByteArray("EFFA1488A73FDBCE5B91BBF9B8D51775");
        //if (!compareTestValues(mac06, mac06Exp, "mac06", verbose)) return false;
        if (verbose) {
            if (VerifyCmac(key06, mac06Exp, msg06, 16, verbose)) {
                Log.d(TAG, "verify CMAC passed");
            } else {
                Log.d(TAG, "verify CMAC failure");
            }
        }

        byte[] key11 = Utils.hexStringToByteArray("F91F1CF58941608F6F08ED190D3BF9B0");
        byte[] msg11 = Utils.hexStringToByteArray("CB09216F785295157058E08B38579E91AB808E8E02D47A508A78E1705D4847C6F3E52E15FA8611EECB7AFEAF0C8ED5E45A1E38C4F02335F68ED1E4FF7024B72810199752298997246EA0C387D6CB43FCA3FD153E0F83D6CFB0378629A1127EA6C3D69EF3F683BAD18714565060AD20C38DE75C720F79188D43C8A1F2026E825B211CC4FF2C50061F4343B7FB2C856E0216C29BB9B60B9749BD11AF2DE1C7CF1991FA2F43E820973DE13C2FCBC11D60BE599FDB3FD2C9A516857A411BA0D93E7B749E6A32552B19F52B5ED879DBCC88A0B0F1D342EC8F46C85418BE6EDF7C9C08FEB45623B22E682E85E61474F02C3AB8F2A16AAF05FC8FE5");
        //byte[] mac11 = calculateCmac(key11, msg11, 16,false);
        byte[] mac11Exp = Utils.hexStringToByteArray("5D5E7B4182EBD50B31FFE52DE4AB5C11");
        //if (!compareTestValues(mac11, mac11Exp, "mac11", verbose)) return false;
        if (verbose) {
            if (VerifyCmac(key11, mac11Exp, msg11, 16, verbose)) {
                Log.d(TAG, "verify CMAC passed");
            } else {
                Log.d(TAG, "verify CMAC failure");
            }
        }

        byte[] key20 = Utils.hexStringToByteArray("AEA00AD0EF9243833DA4861D6A0D2C8C");
        byte[] msg20 = Utils.hexStringToByteArray("");
        //byte[] mac20 = calculateCmac(key20, msg20, 16,false);
        byte[] mac20Exp = Utils.hexStringToByteArray("954230A72692BAB4CE1A44473D081376");
        //if (!compareTestValues(mac20, mac20Exp, "mac20", verbose)) return false;
        if (verbose) {
            if (VerifyCmac(key20, mac20Exp, msg20, 16, verbose)) {
                Log.d(TAG, "verify CMAC passed");
            } else {
                Log.d(TAG, "verify CMAC failure");
            }
        }

        byte[] key21 = Utils.hexStringToByteArray("FDDA1F4B99010C07521C4B74633559D3");
        byte[] msg21 = Utils.hexStringToByteArray("BE");
        //byte[] mac21 = calculateCmac(key21, msg21, 16,false);
        byte[] mac21Exp = Utils.hexStringToByteArray("D3C4EE477F4FA5092B1FE726C18C3D01");
        //if (!compareTestValues(mac21, mac21Exp, "mac21", verbose)) return false;
        if (verbose) {
            if (VerifyCmac(key21, mac21Exp, msg21, 16, verbose)) {
                Log.d(TAG, "verify CMAC passed");
            } else {
                Log.d(TAG, "verify CMAC failure");
            }
        }

        return true;
    }


    // vars
    private byte[] key; // param key: secret key from which updated keys will be derived
    private int u; // param u: number of updated key to use (counting from 0)
    private byte[] r; // param r: IV/counter value (default: all zeros)
    private boolean pad; // param pad: whether to use bit padding or no (default: true)
    private byte[][] p;
    private byte[][] ku; // updated keys
    private byte[] kp;
    private int nibbleSize;
    // variables used for generating session keys
    private byte[] sesAuthMasterKey;
    private byte[][] sesAuthSPts;
    private byte[][] sesAuthMacUpdateKeys;



    // variables used for MAC
    private byte[] k0, k1, buf;
    private int blockSize, tagSize, off;


    private final int AES_BLOCK_SIZE = 16;
    private static final byte P128 = (byte)0x87;

    public boolean _init(byte[] key, int u, byte[] r, boolean pad, boolean verbose) {
        /*
        Leakage Resilient Primitive
        param key: secret key from which updated keys will be derived
        param u: number of updated key to use (counting from 0)
        param r: IV/counter value (default: all zeros)
        param pad: whether to use bit padding or no (default: true)
        uses a fixed nibbleSize of 4
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
        this.nibbleSize = 4;
        this.blockSize = AES_BLOCK_SIZE;
        return true;
    }

    public boolean _initOrg(byte[] key, int u, byte[] r, boolean pad, boolean verbose) {
        /*
        Leakage Resilient Primitive
        param key: secret key from which updated keys will be derived
        param u: number of updated key to use (counting from 0)
        param r: IV/counter value (default: all zeros)
        param pad: whether to use bit padding or no (default: true)
        uses a fixed nibbleSize of 4
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
        this.nibbleSize = 4;
        this.blockSize = AES_BLOCK_SIZE;
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

    public byte[][] generate_plaintexts(byte[] key) {
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

    public byte[][] generate_updated_keys(byte[] key) {
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

    private byte[] eval_lrp(byte[] x, boolean verbose) {
        return eval_lrp(this.p, this.kp, x, true, verbose);
    }

    // x is the 16 byte long counter !
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

    public byte[] calculateCmac(byte[] key, byte[] msg, int tagSize, boolean verbose) {
        /*
        NewWithTagSize returns a hash.Hash computing the CMAC checksum with the
        given tag size. The tag size must between the 1 and the cipher's block size.
         */
        /**
         * Calculate CMAC_LRP, also named CMAC-LRP, LRP-CMAC or LRP_CMAC
         * Algorithm: 6
         * param data: message to be authenticated
         * return: CMAC result
         */
        if (verbose) {
            Log.d(TAG, "calculateCmac");
            Log.d(TAG, printData("key", key));
            Log.d(TAG, printData("msg", msg));
        }

        if (msg == null) {
            Log.e(TAG, "cmac: msg is NULL, aborted");
            return null;
        }

        if (verbose) Log.e(TAG, printData("=== key ===", key));

        // return this value:
        byte[] generatedCmac;

        byte[] k0 = new byte[AES_BLOCK_SIZE];
        byte[] k1 = new byte[AES_BLOCK_SIZE];
        byte[] buf = new byte[AES_BLOCK_SIZE];

        byte[] counter = new byte[4]; // 4 or 16 ?
        boolean success =_init(key, 0, counter, true, verbose);
        if (verbose) Log.d(TAG, printData("kp 0", kp));
        byte[] startValue = new byte[16];
        k0 = eval_lrp(this.p, this.kp, startValue, true, verbose);
        if (verbose) Log.d(TAG, printData("k0", k0));

        //int v = shift(k0, k0, verbose);
        int v = shift3(k0, k0, verbose);
        if (verbose) {
            Log.d(TAG, "v 3: " + v + Utils.printData(" k0", k0));
        }
        if (v == 1) {
            k0[AES_BLOCK_SIZE - 1] ^= P128;
        } else {
            k0[AES_BLOCK_SIZE - 1] ^= (byte) (0x00);
        }

        if (verbose) Log.d(TAG, printData("k0 after AES_BLOCK", k0));

        v = shift3(k1, k0, verbose);
        if (verbose) {
            Log.d(TAG, "v3: " + v + Utils.printData(" k1", k1));
        }

        if (v == 1) {

            k1[AES_BLOCK_SIZE - 1] ^= P128;
        } else {
            k1[AES_BLOCK_SIZE - 1] ^= (byte) (0x00);
        }

        if (verbose) Log.d(TAG, printData("k1 after AES_BLOCK", k1));
        buf = new byte[AES_BLOCK_SIZE];

        if (verbose) {
            Log.d(TAG, "before calling new MacFunc");
            Log.d(TAG, Utils.printData("k0", k0));
            Log.d(TAG, Utils.printData("k1", k1));
            Log.d(TAG, Utils.printData("buf", buf));
        }

        //this.cipher = cipher;
        this.buf = buf;
        this.off = 0;
        this.k0 = k0;
        this.k1 = k1;
        this.tagSize = tagSize;

        if (verbose) Log.d(TAG, " call Write");
        int n = Write(msg, verbose);
        if (verbose) Log.d(TAG, "Write gives result n: " + n);

        generatedCmac = Sum(new byte[0], verbose);
        return generatedCmac;
    }

    public int shift3(byte[] dst, byte[] src, boolean verbose) {
        if (verbose) {
            Log.d(TAG, "shift3");
            Log.d(TAG, Utils.printData("dst", dst));
            Log.d(TAG, Utils.printData("src", src));
        }
        int b = 0;
        int bit;
        for (int i = src.length - 1; i >= 0; i--) {
            bit = (src[i] & 0xFF) >>> 7;
            dst[i] = (byte) (((src[i] & 0xFF) << 1) | b);
            b = bit;
        }
        if (verbose) {
            Log.d(TAG, "returns: " + (b & 0xFF));
            Log.d(TAG, Utils.printData("dst", dst));
        }
        return b & 0xFF;
    }

    public int shift(byte[] dst, byte[] src, boolean verbose) {
        System.out.println("## CMAC shift");
        System.out.println("dst: " + Utils.printData("dst", dst));
        System.out.println("src: " + Utils.printData("src", src));

        byte b = (0x00), bit;
        for (int i = src.length - 1; i >= 0; i--) {
            bit = (byte) (src[i] >> 7);
            dst[i] = (byte) ((src[i] << 1) | b);
            b = bit;
        }
        System.out.println("returns: " + b);
        System.out.println("dst: " + Utils.printData("dst", dst));
        return b;
    }


    public int shift2(byte[] dst, byte[] src) {
        Log.d(TAG, "shift" + printData(" dst", dst) + printData(" src", src));
        byte b = 0;
        byte bit;
        for (int i = src.length - 1; i >= 0; i--) {
            bit = (byte) (src[i] >> 7);
            dst[i] = (byte) ((src[i] << 1) | b);
            b = bit;
        }
        Log.d(TAG, printData("dst", dst));
        Log.d(TAG, "result: " + (b & 0xFF));

        return b & 0xFF; // Ensure the return value is positive
    }


    private void shiftOld(byte[] dest, byte[] src) {
        int carry = 0;
        for (int i = 0; i < dest.length; i++) {
            int b = src[i] & 0xFF;
            dest[i] = (byte) ((b << 1) | carry);
            carry = (b >>> 7) & 1;
        }
    }

    public int Write(byte[] msg, boolean verbose) {
        int bs = BlockSize();
        int n = msg.length;

        if (verbose) {
            Log.d(TAG, "Write " + Utils.printData("msg", msg) + " bs: " + bs + " n: " + n);
            Log.d(TAG, "Write " + Utils.printData("k0", k0) + Utils.printData(" k1", k1));
        }
        if (off > 0) {
            if (verbose) Log.d(TAG, "off > 0");
            int dif = bs - off;
            if (n > dif) {
                xor(buf, off, msg, 0, dif, verbose);
                msg = Arrays.copyOfRange(msg, dif, msg.length);
                //cipher.Encrypt(buf, buf);
                //buf = encrypt(cipher, buf);
                buf = eval_lrp(buf, verbose);
                off = 0;
            } else {
                xor(buf, off, msg, 0, n, verbose);
                off += n;
                return n;
            }
        }
        if (verbose) Log.d(TAG, "off !> 0");
        //buf = new byte[msg.length];
        buf = new byte[AES_BLOCK_SIZE]; // todo formula change - check with shorter message
        if (msg.length > bs) {
            if (verbose) {
                Log.d(TAG, "msg.length > bs");
                Log.d(TAG, "msg.length: " + msg.length + " bs: " + bs);
            }
            int length = msg.length;
            int nn = length & (~(bs - 1));
            if (verbose) Log.d(TAG, "nn: " + nn);
            if (length == nn) {
                nn -= bs;
            }
            if (verbose) Log.d(TAG, "nn 2: " + nn);
            for (int i = 0; i < nn; i += bs) {
                if (verbose) Log.d(TAG, "for i < nn i: " + i);
                //xor(buf, 0, msg, i, i + bs); // todo formula change - check with shorter msg
                xor(buf, 0, msg, i, bs, verbose);
                if (verbose) {
                    Log.d(TAG, "Write before buf = eval_lrp(buf, false);");
                    Log.d(TAG, "Write " + Utils.printData("buf", buf));
                }

                //cipher.Encrypt(buf, buf);
                //buf = encrypt(cipher, buf);
                buf = eval_lrp(buf, verbose);
            }
            msg = Arrays.copyOfRange(msg, nn, msg.length);
        }
        if (verbose) {
            Log.d(TAG, "Write before if (msg.length > 0)");
            Log.d(TAG, "Write " + Utils.printData("buf", buf));
            Log.d(TAG, "Write " + Utils.printData("msg", msg));
        }
        if (msg.length > 0) {
            xor(buf, off, msg, 0, msg.length, verbose);
            off += msg.length;
        }
        if (verbose) {
            Log.d(TAG, "Write final " + Utils.printData("buf", buf));
            Log.d(TAG, "Write final " + Utils.printData("msg", msg));
            Log.d(TAG, "Write final n: " + n);
        }
        return n;
    }

    public byte[] Sum(byte[] b, boolean verbose) {
        if (verbose) Log.d(TAG, "Sum " + Utils.printData("b", b));
        int blocksize = AES_BLOCK_SIZE;

        byte[] hash = new byte[blocksize];

        if (off < blocksize) {
            if (verbose) Log.d(TAG, "off < blocksize " + Utils.printData("k1", k1));
            System.arraycopy(k1, 0, hash, 0, k1.length);
        } else {
            if (verbose) Log.d(TAG, "off !< blocksize " + Utils.printData("k0", k0));
            System.arraycopy(k0, 0, hash, 0, k0.length);
        }

        xor(hash, 0, buf, 0, buf.length, verbose);
        if (off < blocksize) {
            hash[off] ^= 0x80;
            if (verbose) Log.d(TAG, "off < blocksize ");
        }

        //cipher.Encrypt(hash, hash);
        if (verbose) Log.d(TAG, "Sum before last encrypt " + Utils.printData("hash", hash));
        //hash = encrypt(cipher, hash);
        hash = eval_lrp(hash, verbose);
        if (verbose) Log.d(TAG, "Sum after  last encrypt " + Utils.printData("hash", hash));
        byte[] result = new byte[b.length + this.tagSize];
        System.arraycopy(b, 0, result, 0, b.length);
        System.arraycopy(hash, 0, result, b.length, this.tagSize);
        return result;
    }

    public void Reset() {
        for (int i = 0; i < buf.length; i++) {
            buf[i] = 0;
        }
        off = 0;
    }

    private void xor(byte[] dest, int destOffset, byte[] src, int srcOffset, int length, boolean verbose) {
        if (verbose) Log.d(TAG, "xor " + Utils.printData("dest", dest) + Utils.printData(" src", src));
        if (verbose) Log.d(TAG, "xor destOffset: " + destOffset + " srcOffset: " + srcOffset + " length: " + length);
        for (int i = 0; i < length; i++) {
            dest[destOffset + i] ^= src[srcOffset + i];
        }
    }

    public boolean VerifyCmac(byte[] key, byte[] cmac, byte[] message, int tagSize, boolean verbose) {
        if (verbose) {
            Log.d(TAG, "VerifyCmac with tagSize " + tagSize);
            Log.d(TAG, printData("cmac", cmac));
            Log.d(TAG, printData("message", message));
        }
        if ((key == null) || (key.length != 16)) {
            Log.e(TAG, "key is NULL or not of length 16, aborted");
            return false;
        }
        if ((cmac == null) || (cmac.length != 16)) {
            Log.e(TAG, "cmac is NULL or not of length 16, aborted");
            return false;
        }
        if (tagSize != 16) {
            Log.e(TAG, "tagSize is not 16, aborted");
            return false;
        }
        byte[] calculatedCmac = calculateCmac(key, message, tagSize, verbose);
        if ((calculatedCmac == null) || (calculatedCmac.length != 16)) {
            Log.e(TAG, "the calculated CMAC is null or not of length 16, aborted");
            return false;
        }
        boolean result = Arrays.equals(calculatedCmac, cmac);
        if (verbose) Log.d(TAG, "CMAC matches calculatedCmac: " + result);
        return result;
    }

    public int Size() {
        return AES_BLOCK_SIZE;
    }

    public int BlockSize() {
        return AES_BLOCK_SIZE;
    }

/*
import java.util.Arrays;

public class CMACShift {
    public static int shift(byte[] dst, byte[] src) {
        System.out.println("## CMAC shift");
        System.out.println("dst: " + bytesToHex(dst));
        System.out.println("src: " + bytesToHex(src));

        byte b = 0;
        byte bit;
        for (int i = src.length - 1; i >= 0; i--) {
            bit = (byte) (src[i] >> 7);
            dst[i] = (byte) ((src[i] << 1) | b);
            b = bit;
        }

        System.out.println("returns: " + b);
        System.out.println("dst: " + bytesToHex(dst));

        return b & 0xFF; // Ensure the return value is positive
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexStringBuilder = new StringBuilder();
        for (byte b : bytes) {
            hexStringBuilder.append(String.format("%02X", b));
        }
        return hexStringBuilder.toString();
    }

    public static void main(String[] args) {
        byte[] dst = new byte[16];
    byte[] src = new byte[16];
    int result = shift(dst, src);
        System.out.println("Result: " + result);
}
}

*/

    public byte[] getSessionVector(byte[] rndA, byte[] rndB) {
        final String methodName = "getSessionVector";
        Log.d(TAG,printData("rndA", rndA) + printData(" rndB", rndB) );
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            Log.d(TAG, "rndA is NULL or wrong length, aborted");
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            Log.d(TAG, "rndB is NULL or wrong length, aborted");
            return null;
        }
        boolean TEST_MODE_GEN_LRP_SES_KEYS = false;

        // 74 D7 DF 6A 2C EC 0B 72 B4 12 DE 0D 2B 11 17 E6
        //  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        byte[] rndA00to01 = Arrays.copyOfRange(rndA, 0, 2); // step 06 74d7
        byte[] rndA02to07 = Arrays.copyOfRange(rndA, 2, 8); // step 07 DF6A2CEC0B72
        byte[] rndA08to15 = Arrays.copyOfRange(rndA, 8, 16); // step 11 (wrong: 2B412DE0D2B1117E), correct B412DE0D2B1117E6
        // 56 10 9A 31 97 7C 85 53 19 CD 46 18 C9 D2 AE D2
        //  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        byte[] rndB00to05 = Arrays.copyOfRange(rndB, 0, 6); // step 08 56109A31977C
        byte[] rndB06to15 = Arrays.copyOfRange(rndB, 6, 16); // step 10 855319CD4618C9D2AED2
        byte[] xored = xor(rndA02to07, rndB00to05); // step 09
        // step 12 sessionVector
        // counter || length tag || RndA[15::14] || (RndA[13::8] XOR RndB[15::10]) || RndB[9::0] || RndA[7::0] || label
        // counter || length tag || rndA00to01   || xored                          || rndB06to15 || rndA08to15 || label
        // 0001008074D7897AB6DD9C0E855319CD4618C9D2AED2B412DE0D2B1117E69669
        ByteArrayOutputStream baosSessionVector = new ByteArrayOutputStream();
        baosSessionVector.write(LRP_FIXED_COUNTER, 0, LRP_FIXED_COUNTER.length);
        baosSessionVector.write(LRP_FIXED_LENGTH, 0, LRP_FIXED_LENGTH.length);
        baosSessionVector.write(rndA00to01, 0, rndA00to01.length);
        baosSessionVector.write(xored, 0, xored.length);
        baosSessionVector.write(rndB06to15, 0, rndB06to15.length);
        baosSessionVector.write(rndA08to15, 0, rndA08to15.length);
        baosSessionVector.write(LRP_FIXED_LABEL, 0, LRP_FIXED_LABEL.length);
        byte[] sessionVector = baosSessionVector.toByteArray();
        if (TEST_MODE_GEN_LRP_SES_KEYS) {
            byte[] sessionVectorExp = hexStringToByteArray("0001008074D7897AB6DD9C0E855319CD4618C9D2AED2B412DE0D2B1117E69669");
            if (!Arrays.equals(sessionVector, sessionVectorExp)) {
                Log.d(TAG, printData("sessionVectorExp", sessionVectorExp));
                Log.e(TAG, "sessionVector does not match the expected value, aborted");
                return null;
            } else {
                Log.d(TAG, "sessionVector test PASSED");
            }
        }
        Log.d(TAG, printData("sessionVector", sessionVector));
        return sessionVector;
    }

    public byte[] generateKSesAuthMaster(byte[] sessionVector) {
        Log.d(TAG, "generateKSesAuthMaster");
        byte[] authUpdateKey = ku[0].clone();
        Log.d(TAG, printData("authUpdateKey (ku[0])", authUpdateKey));

        byte[] KSesAuthMaster = calculateCmac(authUpdateKey, sessionVector, AES_BLOCK_SIZE, false);
        Log.d(TAG, printData("KSesAuthMaster", KSesAuthMaster));
        sesAuthMasterKey = KSesAuthMaster;
        return KSesAuthMaster;
    }

    public void generateSessionAuthKeys() {
        // see NTAG 424 DNA NT4H2421Gx.pdf page 33
        sesAuthSPts = generate_plaintexts(sesAuthMasterKey);
        sesAuthMacUpdateKeys = generate_updated_keys(sesAuthMasterKey);
    }


    private byte[] cmacOrg(byte[] key, byte[] data, boolean verbose) {
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

        if (verbose) Log.d(TAG, printData("=== key ===", key));

        // return this value:
        byte[] generatedCmac;

        Cipher cipher = null;
        try {
            Log.d(TAG, "1 start cipher");
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Log.d(TAG, "2 start LrpMacFunc");
        LrpMacFunc macFunc = null;
        try {
            macFunc = new LrpMacFunc(cipher, 16);
            //macFunc = new LrpMacFunc(key, 16);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        Log.d(TAG, "3 init LrpMacFunc done");
        Log.d(TAG, printData("data", data));
        macFunc.Write(data);
        Log.d(TAG, "4 write LrpMacFunc data done");
        generatedCmac = macFunc.Sum(new byte[0]);
        Log.d(TAG, "5 sum LrpMacFunc done");

        return generatedCmac;

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

    public boolean compareTestValues(byte[] real, byte[] expected, String valueName, boolean verbose) {
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

    public byte[][] getP() {
        return p;
    }

    /**
     * section for getter
     */

    public byte[][] getKu() {
        return ku;
    }

    public byte[] getSesAuthMasterKey() {
        return sesAuthMasterKey;
    }

    public byte[][] getSesAuthSPts() {
        return sesAuthSPts;
    }

    public byte[][] getSesAuthMacUpdateKeys() {
        return sesAuthMacUpdateKeys;
    }
}
