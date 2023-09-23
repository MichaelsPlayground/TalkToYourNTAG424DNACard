package de.androidcrypto.talktoyourntag424dnacard;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class Shamir {
    // source: https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Protocol/SecretSharing.py

    public static class Element {
        private final long value;
        private static final long irrPoly = 1 + 2 + 4 + 128 + (1L << 128);

        public Element(byte[] encodedValue) {
            if (encodedValue.length == 16) {
                this.value = bytesToLong(encodedValue);
            } else {
                throw new IllegalArgumentException("The encoded value must be a 16-byte array");
            }
        }

        public Element(long value) {
            this.value = value;
        }

        public byte[] encode() {
            return longToBytes(value, 16);
        }

        public Element multiply(Element factor) {
            long f1 = this.value;
            long f2 = factor.value;
            long mask1 = 1L << 128;
            long z = 0;

            if (f2 > f1) {
                long temp = f1;
                f1 = f2;
                f2 = temp;
            }

            while (f2 != 0) {
                if ((f2 & 1) != 0) {
                    z ^= f1;
                }
                f1 <<= 1;
                f2 >>= 1;

                long mask2 = 1L << 128;
                long v = f1;

                while (v >= mask2) {
                    if ((v & mask2) != 0) {
                        v ^= irrPoly;
                    }
                    mask2 >>= 1;
                }
            }

            return new Element(z);
        }

        public Element add(Element term) {
            return new Element(this.value ^ term.value);
        }

        public Element inverse() {
            long r0 = this.value;
            long r1 = irrPoly;
            long s0 = 1;
            long s1 = 0;

            while (r1 > 0) {
                long[] divResult = divideGf2(r0, r1);
                long q = divResult[0];
                long newR0 = r1;
                long newS0 = s1;

                r0 = newR0;
                s0 = newS0;
                r1 ^= multiplyGf2(q, r1);
                s1 ^= multiplyGf2(q, s1);
            }

            return new Element(s0);
        }

        public Element power(int exponent) {
            Element result = new Element(this.value);
            for (int i = 0; i < exponent - 1; i++) {
                result = result.multiply(this);
            }
            return result;
        }

        private static long[] divideGf2(long a, long b) {
            long[] result = new long[2];
            if (a < b) {
                result[0] = 0;
                result[1] = a;
                return result;
            }

            int d = Long.numberOfLeadingZeros(b) - Long.numberOfLeadingZeros(a);
            long q = 0;

            while (d >= 0) {
                q ^= (1L << d);
                a ^= multiplyGf2(b, (1L << d));
                d = Long.numberOfLeadingZeros(b) - Long.numberOfLeadingZeros(a);
            }

            result[0] = q;
            result[1] = a;
            return result;
        }
    }


    private static byte[] longToBytes(long value, int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = (byte) (value >>> (8 * (length - i - 1)));
        }
        return result;
    }

    private static long bytesToLong(byte[] bytes) {
        long result = 0;
        for (int i = 0; i < bytes.length; i++) {
            result |= ((long) (bytes[i] & 0xFF) << (8 * (bytes.length - i - 1)));
        }
        return result;
    }

    private static long multiplyGf2(long f1, long f2) {
        if (f2 > f1) {
            long temp = f1;
            f1 = f2;
            f2 = temp;
        }
        long z = 0;
        while (f2 != 0) {
            if ((f2 & 1) != 0) {
                z ^= f1;
            }
            f1 <<= 1;
            f2 >>= 1;
            long mask2 = 1L << 128;
            long v = f1;
            while (v >= mask2) {
                if ((v & mask2) != 0) {
                    v ^= Element.irrPoly;
                }
                mask2 >>= 1;
            }
        }
        return z;
    }

    public static void main(String[] args) {
        int k = 3; //
    }
}
