package de.androidcrypto.talktoyourntag424dnacard.lrp;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Util {

    public static byte[] decryptWith(byte[] key, byte[] data) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encryptWith(byte[] key, byte[] data) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static int[] nibbles(byte[] bytes) {
        int[] nibbles = new int[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int msb = 0b11110000 & bytes[i];
            msb = msb >> 4;
            int lsb = 0b00001111 & bytes[i];
            nibbles[i * 2] = msb;
            nibbles[i * 2 + 1] = lsb;
        }
        return nibbles;
    }

}
