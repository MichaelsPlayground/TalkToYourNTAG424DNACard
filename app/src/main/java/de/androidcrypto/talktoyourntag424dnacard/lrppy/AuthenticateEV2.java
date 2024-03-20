package de.androidcrypto.talktoyourntag424dnacard.lrppy;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.Validate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class AuthenticateEV2 {
    private final byte[] authKey;
    private byte[] rnda;
    private byte[] rndb;

    public AuthenticateEV2(byte[] authKey) {
        this.authKey = authKey;
    }

    public byte[] init(byte keyNo) {
        byte[] params = new byte[]{keyNo, 0x00};
        return ByteBuffer.allocate(7)
                .put((byte) 0x90)
                .put((byte) 0x71)
                .put((byte) 0x00)
                .put((byte) 0x00)
                .put((byte) 0x02)
                .put(params)
                .put((byte) 0x00)
                .array();
    }

    public byte[] generateRnda() {
        byte[] rnda = new byte[16];
        new java.util.Random().nextBytes(rnda);
        return rnda;
    }

    public byte[] part1(byte[] part1Resp) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Validate.isTrue(part1Resp.length == 18, "R-APDU length");
        Validate.isTrue(Arrays.equals(Arrays.copyOfRange(part1Resp, 16, 18), new byte[]{(byte) 0x91, (byte) 0xAF}), "status code 91AF");

        byte[] rndbEnc = Arrays.copyOf(part1Resp, 16);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(authKey, "AES"), new javax.crypto.spec.IvParameterSpec(new byte[16]));
        rndb = cipher.doFinal(rndbEnc);
        rnda = generateRnda();
        byte[] rndbP = byteRotLeft(rndb);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(authKey, "AES"), new javax.crypto.spec.IvParameterSpec(new byte[16]));
        byte[] resp = cipher.doFinal(ArrayUtils.addAll(rnda, rndbP));
        return ByteBuffer.allocate(39)
                .put((byte) 0x90)
                .put((byte) 0xAF)
                .put((byte) 0x00)
                .put((byte) 0x00)
                .put((byte) 0x20)
                .put(resp)
                .put((byte) 0x00)
                .array();
    }

    public CryptoComm part2(byte[] part2Resp) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchProviderException {
        Validate.isTrue(part2Resp.length == 34, "R-APDU length");
        Validate.isTrue(Arrays.equals(Arrays.copyOfRange(part2Resp, 32, 34), new byte[]{(byte) 0x91, (byte) 0x00}), "status code 9100");

        byte[] enc = Arrays.copyOf(part2Resp, 32);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(authKey, "AES"), new javax.crypto.spec.IvParameterSpec(new byte[16]));
        byte[] resp = cipher.doFinal(enc);
        InputStream respStream = new ByteArrayInputStream(resp);
        byte[] ti = new byte[4];
        respStream.read(ti);
        byte[] rndaP = new byte[16];
        respStream.read(rndaP);
        byte[] pdcap2 = new byte[6];
        respStream.read(pdcap2);
        byte[] pcdcap2 = new byte[6];
        respStream.read(pcdcap2);
        byte[] recvRnda = byteRotRight(rndaP);
        Validate.isTrue(Arrays.equals(rnda, recvRnda), "generated RndA == decrypted RndA");

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(rnda, 0, 2);
        byte[] xorResult = new byte[6];
        for (int i = 0; i < 6; i++) {
            xorResult[i] = (byte) (rnda[i + 2] ^ rndb[i]);
        }
        stream.write(xorResult, 0, xorResult.length);
        stream.write(rndb, rndb.length - 10, 10);
        stream.write(rnda, rnda.length - 8, 8);

        ByteArrayOutputStream sv1stream = new ByteArrayOutputStream();
        sv1stream.write(new byte[]{(byte) 0xA5, (byte) 0x5A, 0x00, 0x01, 0x00, (byte) 0x80});
        sv1stream.write(stream.toByteArray());
        byte[] sv1 = sv1stream.toByteArray();

        ByteArrayOutputStream sv2stream = new ByteArrayOutputStream();
        sv2stream.write(new byte[]{0x5A, (byte) 0xA5, 0x00, 0x01, 0x00, (byte) 0x80});
        sv2stream.write(stream.toByteArray());
        byte[] sv2 = sv2stream.toByteArray();

        Mac mac = Mac.getInstance("AESCMAC", "BC");
        mac.init(new SecretKeySpec(authKey, "AES"));
        byte[] kSesAuthEnc = mac.doFinal(sv1);

        mac.init(new SecretKeySpec(authKey, "AES"));
        byte[] kSesAuthMac = mac.doFinal(sv2);

        //return new CryptoComm(kSesAuthMac, kSesAuthEnc, ti, pdcap2, pcdcap2);
        return new CryptoComm(kSesAuthMac, kSesAuthEnc, ti, 0, pdcap2, pcdcap2);
    }

    private byte[] byteRotLeft(byte[] x) {
        return ArrayUtils.addAll(Arrays.copyOfRange(x, 1, x.length), new byte[]{x[0]});
    }

    private byte[] byteRotRight(byte[] x) {
        return ArrayUtils.addAll(new byte[]{x[x.length - 1]}, Arrays.copyOfRange(x, 0, x.length - 1));
    }
}

