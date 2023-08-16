package de.androidcrypto.talktoyourntag424dnacard.lrp;

import static de.androidcrypto.talktoyourntag424dnacard.lrp.Constants.blocksize;
import static de.androidcrypto.talktoyourntag424dnacard.lrp.Util.nibbles;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class LrpForMAC extends LrpCipher {

    public LrpForMAC(LrpMultiCipher Multi, byte[] Key, long Counter, boolean Encrypting) {
        super(Multi, Key, Counter, Encrypting);
    }

    public void encrypt(byte[] dst, byte[] src) {
        byte[] result = evalLRP(nibbles(src), true);
        System.arraycopy(result, 0, dst, 0, blocksize);
    }

    public byte[] cmac(byte[] msg) throws Exception {
        Mac h = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(this.getKey(), "HmacSHA256");
        h.init(keySpec);
        h.update(msg);
        return h.doFinal();
    }

    public byte[] shortCMAC(byte[] msg) throws Exception {
        byte[] mac = cmac(msg);
        return new byte[] { mac[1], mac[3], mac[5], mac[7], mac[9], mac[11], mac[13], mac[15] };
    }

}
