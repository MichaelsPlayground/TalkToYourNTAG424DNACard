package de.androidcrypto.talktoyourntag424dnacard.lrppy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.zip.CRC32;

public class CryptoComm {
    private final byte[] k_ses_auth_mac;
    private final byte[] k_ses_auth_enc;
    private final byte[] ti;
    private int cmd_counter;
    private final byte[] pdcap2;
    private final byte[] pcdcap2;

    public CryptoComm(byte[] k_ses_auth_mac, byte[] k_ses_auth_enc, byte[] ti, int cmd_counter, byte[] pdcap2, byte[] pcdcap2) {
        this.k_ses_auth_mac = k_ses_auth_mac;
        this.k_ses_auth_enc = k_ses_auth_enc;
        this.ti = ti;
        this.cmd_counter = cmd_counter;
        this.pdcap2 = pdcap2;
        this.pcdcap2 = pcdcap2;
    }

    public byte[] calc_raw_data(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        CRC32 crc = new CRC32();
        crc.update(data);
        long crcValue = crc.getValue();
        byte[] crcBytes = ByteBuffer.allocate(Long.BYTES).putLong(crcValue).array();
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        for (int i = 0; i < crcBytes.length; i += 2) {
            byteStream.write(crcBytes[i + 1]);
        }
        return byteStream.toByteArray();
    }

    public byte[] wrap_cmd(int ins, CommMode mode, byte[] header, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        if (header == null) {
            header = new byte[0];
        }
        if (data == null) {
            data = new byte[0];
        }
        int payload_len = header.length + data.length;
        byte[] apdu = ByteBuffer.allocate(6 + payload_len).put((byte) 0x90).put((byte) ins).putShort((short) 0x0000).put((byte) payload_len).put(header).put(data).put((byte) 0x00).array();
        if (mode == CommMode.PLAIN) {
            cmd_counter++;
            return apdu;
        } else if (mode == CommMode.MAC) {
            return sign_apdu(apdu);
        } else if (mode == CommMode.FULL) {
            return encrypt_apdu(apdu, header.length);
        }
        throw new RuntimeException("Invalid CommMode specified.");
    }

    public byte[] sign_apdu(byte[] apdu) throws NoSuchAlgorithmException, InvalidKeyException {
        if (ti == null) {
            throw new RuntimeException("TI was not set.");
        }
        if (apdu[0] != (byte) 0x90 || apdu[2] != (byte) 0x00 || apdu[3] != (byte) 0x00 || apdu[apdu.length - 1] != (byte) 0x00 || apdu[4] != apdu.length - 6) {
            throw new RuntimeException("Invalid APDU format.");
        }
        byte[] cmd = Arrays.copyOfRange(apdu, 1, 2);
        byte[] cmd_cntr_b = ByteBuffer.allocate(2).putShort((short) cmd_counter).array();
        byte[] ti = this.ti;
        byte[] data = Arrays.copyOfRange(apdu, 5, apdu.length - 1);
        byte[] mact = calc_raw_data(concatenate(concatenate(concatenate(cmd, cmd_cntr_b), ti), data));
        byte new_len = (byte) (apdu[4] + mact.length);
        byte[] new_apdu = ByteBuffer.allocate(6 + new_len).put((byte) 0x90).put(apdu[1]).putShort((short) 0x0000).put(new_len).put(data).put(mact).put((byte) 0x00).array();
        cmd_counter++;
        return new_apdu;
    }

    public byte[] encrypt_apdu(byte[] apdu, int data_offset) throws NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        if (apdu[0] != (byte) 0x90 || apdu[2] != (byte) 0x00 || apdu[3] != (byte) 0x00 || apdu[apdu.length - 1] != (byte) 0x00 || apdu[4] != apdu.length - 6) {
            throw new RuntimeException("Invalid APDU format.");
        }
        byte[] header = new byte[data_offset];
        System.arraycopy(apdu, 5, header, 0, data_offset);

        byte[] iv_b = new byte[12];
        System.arraycopy(new byte[] { (byte) 0xA5, (byte) 0x5A }, 0, iv_b, 0, 2);
        System.arraycopy(ti, 0, iv_b, 2, ti.length);
        ByteBuffer.wrap(iv_b, 6, 2).putShort((short) cmd_counter);
        SecretKeySpec secretKey = new SecretKeySpec(k_ses_auth_enc, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.doFinal(iv_b);

        ByteArrayOutputStream plainstream = new ByteArrayOutputStream();
        plainstream.write(apdu, 5 + data_offset, apdu.length - data_offset - 6);

        if (apdu.length - data_offset - 6 == 0) {
            return sign_apdu(apdu);
        }
        plainstream.write((byte) 0x80);

        while (plainstream.size() % 16 != 0) {
            plainstream.write((byte) 0x00);
        }

        byte[] enc;
        cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        enc = cipher.doFinal(plainstream.toByteArray());

        byte[] new_len = new byte[] { (byte) (header.length + enc.length) };

        ByteArrayOutputStream encryptedApdu = new ByteArrayOutputStream();
        encryptedApdu.write((byte) 0x90);
        encryptedApdu.write(apdu[1]);
        encryptedApdu.write(0x00);
        encryptedApdu.write(0x00);
        encryptedApdu.write(new_len[0]);
        encryptedApdu.write(header);
        encryptedApdu.write(enc);
        encryptedApdu.write((byte) 0x00);
        return sign_apdu(encryptedApdu.toByteArray());
    }

    public byte[] parse_response(byte[] res) throws NoSuchAlgorithmException, InvalidKeyException {
        if (res[res.length - 2] != (byte) 0x91) {
            throw new RuntimeException("Response code 91xx not found");
        }
        byte[] status = new byte[] { res[res.length - 2], res[res.length - 1] };
        byte[] mact = new byte[8];
        byte[] data = new byte[res.length - 10];

        System.arraycopy(res, res.length - 10, mact, 0, 8);
        System.arraycopy(res, 0, data, 0, res.length - 10);

        byte[] our_mact = calc_raw_data(concatenate(concatenate(concatenate(new byte[] { status[1] }, ByteBuffer.allocate(2).putShort((short) cmd_counter).array()), ti), data));

        if (!Arrays.equals(mact, our_mact)) {
            throw new RuntimeException("Received MAC != calculated MAC");
        }
        return data;
    }

    public byte[] decrypt_response(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        if (data.length == 0) {
            return new byte[0];
        }

        byte[] iv_b = new byte[12];
        System.arraycopy(new byte[] { (byte) 0x5A, (byte) 0xA5 }, 0, iv_b, 0, 2);
        System.arraycopy(ti, 0, iv_b, 2, ti.length);
        ByteBuffer.wrap(iv_b, 6, 2).putShort((short) cmd_counter);
        SecretKeySpec secretKey = new SecretKeySpec(k_ses_auth_enc, "AES");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipher.doFinal(iv_b);
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] unwrap_res(byte[] res) throws NoSuchAlgorithmException, InvalidKeyException {
        if (res[res.length - 2] != (byte) 0x91) {
            throw new RuntimeException("Response code 91xx not found");
        }
        byte[] status_code = new byte[] { res[res.length - 2], res[res.length - 1] };
        byte[] data = parse_response(res);
        return decrypt_response(data);
    }

    private byte[] concatenate(byte[] dataA, byte[] dataB) {
        byte[] concatenated = new byte[dataA.length + dataB.length];
        for (int i = 0; i < dataA.length; i++) {
            concatenated[i] = dataA[i];
        }

        for (int i = 0; i < dataB.length; i++) {
            concatenated[dataA.length + i] = dataB[i];
        }
        return concatenated;
    }
}
