/**
 * Copyright 2016 National Cyber Security Centre, Netherlands Forensic Institute
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.minvenj.pef.ffx;

import static java.lang.Math.ceil;
import static java.lang.Math.log;
import static java.util.Arrays.copyOfRange;

import static nl.minvenj.pef.util.Util.argNotNull;
import static nl.minvenj.pef.util.Util.concatBytes;
import static nl.minvenj.pef.util.Util.even;
import static nl.minvenj.pef.util.Util.modPosDiv;
import static nl.minvenj.pef.util.Util.padZeroLeft;
import static nl.minvenj.pef.util.Util.stringNumInRadix;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypter for Format Preserving Encryption, a partial implementation of:
 *
 *      http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf
 *      http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf
 *
 * The specific implementation is the one from the addendum. The code style and structure is
 * kept as close as possible to the original specification.
 *
 * Main differences between with respect to the specification:
 *     * supplying an arbitrary mapping is not possible
 *     * only a radix in [2..36] is supported (specification max is 2^16)
 *     * only alphanumerical strings are allowed as input
 *
 * @author Netherlands Forensic Institute.
 */
public final class FFX {

    /** Maximum valid radix. */
    public static final int MAX_RADIX = 36;

    private static final BigInteger BIGINTEGER_0XFF = BigInteger.valueOf(0xFF);

    // cache logarithm of 2
    private static final double LOG_2 = log(2);

    // cache first three values of p as they are always the same
    private static final byte[] FIRST_THREE_OF_P = concatBytes(sI(1, 1), sI(2, 1), sI(1, 1));

    private final int _radix;
    private final AES _aes;

    /**
     * Constructs a new FFX based encrypter.
     *
     * The key will be used as the key for the AES based rounding function.
     *
     * @param key 128-bit AES key
     * @param radix the radix of the input/output message of the encryption; radix must be between [2..36] inclusive
     * @throws InvalidKeyException when given key is not valid
     */
    public FFX(final byte[] key, final int radix) throws InvalidKeyException {
        // check if key is {0,1}^128
        if (key.length != 16) {
            throw new IllegalArgumentException("key must be 128-bit: " + Arrays.toString(key));
        }
        if (radix < 2 || radix > MAX_RADIX) {
            throw new IllegalArgumentException(String.format("illegal radix value: %d, must be in range [2, %d]", radix, MAX_RADIX));
        }

        _radix = radix;
        _aes = new AES(key);
    }

    /**
     * Encrypt a message.
     *
     * An optional tweak can be given (if not, an empty array). A tweak is non-secret
     * and is used in addition to the key for encryption. (think password hashing salt)
     *
     * @param tweak array of bytes to use as tweak
     * @param message the message to encrypt
     * @return the encrypted message
     */
    public String encrypt(final byte[] tweak, final String message) {
        validateInput(tweak, message);

        final int n = message.length();
        final int l = split(n);
        final int r = rnds(n);

        String a = message.substring(0, l);
        String b = message.substring(l, n);

        // "length of byte string BYTE* in bytes"
        final int t = tweak.length;
        // as stated in the specification, the first four values of p are fixed, the last two are constant for a given n
        // calculate p here because it stays the same through all rounds of an encryption
        final byte[] p = concatBytes(FIRST_THREE_OF_P, sI(_radix, 3), sI(rnds(n), 1), sI(split(n), 1), sI(n, 4), sI(t, 4));

        for (int i = 0; i < r; i++) {
            final String c = add(a, f(n, tweak, i, b, p), _radix);
            a = b;
            b = c;

            b = padZeroLeft(b, n - a.length() - b.length());
        }

        return (a + b).toUpperCase();
    }

    /**
     * Decrypt a message.
     *
     * In order to correctly decrypt a message, the original tweak which was given
     * to {@link#encrypt(tweak, message)} should be the same as this one.
     *
     * @param tweak array of bytes to use as tweak
     * @param message the message to decrypt
     * @return the decrypted message
     */
    public String decrypt(final byte[] tweak, final String message) {
        validateInput(tweak, message);

        final int n = message.length();
        final int l = split(n);
        final int r = rnds(n);

        String a = message.substring(0, l);
        String b = message.substring(l, n);

        final int t = tweak.length;
        final byte[] p = concatBytes(FIRST_THREE_OF_P, sI(_radix, 3), sI(rnds(n), 1), sI(split(n), 1), sI(n, 4), sI(t, 4));

        for (int i = r - 1; i >= 0; i--) {
            final String c = b;
            b = a;
            a = sub(c, f(n, tweak, i, b, p), _radix);

            a = padZeroLeft(a, n - a.length() - b.length());
        }

        return (a + b).toUpperCase();
    }

    private void validateInput(final byte[] tweak, final String message) {
        // check if tweak is repn(BYTE, 0..maxlen) with BYTE = {0,1}^8 and maxlen = 2^32 - 1
        // this is not necessary since in this implementation it is a byte array

        argNotNull("tweak", tweak);
        argNotNull("message", message);

        // check if length of message is [minlen..maxlen] with minlen = radix >= 10 ? 2 : 8 and maxlen = 2^32 -1
        if (_radix >= 10 ? message.length() < 2 : message.length() < 8) {
            throw new IllegalArgumentException(String.format("invalid message length: %d", message.length()));
        }
        // check if message is over alphabet Chars = {0..radix-1}
        if (!stringNumInRadix(message, _radix)) {
            throw new IllegalArgumentException(String.format("message [%s] is not a number in base %d", message, _radix));
        }
    }

    /** Maximally balanced Feistel. */
    private int split(final int n) {
        // take floor of the division
        return n / 2;
    }

    /** Number of rounds. */
    private int rnds(final int n) {
        return 10;
    }

    /** Blockwise addition of two strings interpreted with given radix. */
    private String add(final String a, final String b, final int radix) {
        return new BigInteger(a, radix)
            .add(new BigInteger(b, radix))
            .mod(BigInteger.valueOf(_radix).pow(a.length()))
            .toString(radix);
    }

    /** Blockwise subtraction of two strings interpreted with given radix. */
    private String sub(final String a, final String b, final int radix) {
        return new BigInteger(a, radix)
            .subtract(new BigInteger(b, radix))
            .mod(BigInteger.valueOf(_radix).pow(a.length()))
            .toString(radix);
    }

    /**
     * AES-based round function.
     *
     * @param n original message length
     * @param tweak the tweak byte string (array of bytes)
     * @param i current round number
     * @param part partial text
     * @param p cached value of p
     * @return AES transformed partial text
     */
    private String f(final int n, final byte[] tweak, final int i, final String part, final byte[] p) {
        final int t = tweak.length;
        final int beta = (int) ceil(n / 2.0);
        final int b = (int) ceil(ceil(beta * (log(_radix) / LOG_2)) / 8.0);
        final int d = 4 * (int) (ceil(b / 4.0));
        final int m = (int) (even(i) ? n / 2 : ceil(n / 2.0));

        final byte[] q = concatBytes(tweak, sI(0, modPosDiv(-t - b - 1, 16)), sI(i, 1), sI(new BigInteger(part, _radix), b));
        final byte[] y = _aes.encryptCBC(concatBytes(p, q));

        int s = 1;
        byte[] concatY = y;
        while (concatY.length < d + 4) {
            final byte[] xor = xor(y, sI(s++, 16));
            final byte[] ecb = _aes.encryptECB(xor);
            concatY = concatBytes(concatY, ecb);
        }
        concatY = copyOfRange(concatY, 0, d + 4);
        // NUM2(Y) is interpreting in binary, so just construct a BigInteger from the byte array
        final BigInteger numy = new BigInteger(1, concatY);

        final BigInteger z = numy.mod(BigInteger.valueOf(_radix).pow(m));
        final String strZ = z.toString(_radix);
        return padZeroLeft(strZ, m - strZ.length());
    }

    /** Returns the i-byte string that encodes the number s = [0 .. 2^8i - 1]. */
    private static byte[] sI(final long s, final int i) {
        final byte[] bytes = new byte[i];
        long ss = s;
        for (int index = bytes.length - 1; index >= 0 && ss > 0; index--) {
            bytes[index] = (byte) (ss & 0xFF);
            ss >>= 8;
        }
        return bytes;
    }

    /** Returns the i-byte string that encodes the number s = [0 .. 2^8i - 1]. */
    private byte[] sI(final BigInteger s, final int i) {
        final byte[] bytes = new byte[i];
        BigInteger ss = s;
        for (int index = bytes.length - 1; index >= 0 && ss.compareTo(BigInteger.ZERO) > 0; index--) {
            bytes[index] = ss.and(BIGINTEGER_0XFF).byteValue();
            ss = ss.shiftRight(8);
        }
        return bytes;
    }

    /** XOR two equal length byte arrays. */
    private byte[] xor(final byte[] x, final byte[] y) {
        final byte[] xor = new byte[x.length];
        for (int i = 0; i < xor.length; i++) {
            xor[i] = (byte) (x[i] ^ y[i]);
        }
        return xor;
    }

    private static class AES {

        // calculating the CBC-MAC of a message requires CBC mode with a zero initialization vector
        private final IvParameterSpec _iv = new IvParameterSpec(new byte[16]);
        private final SecretKeySpec _key;

        private final Cipher _cbcMacAes;
        private final Cipher _ecbAes;

        AES(final byte[] key) throws InvalidKeyException {
            _key = new SecretKeySpec(key, "AES");

            try {
                _cbcMacAes = Cipher.getInstance("AES/CBC/NoPadding");
                _cbcMacAes.init(Cipher.ENCRYPT_MODE, _key, _iv);

                _ecbAes = Cipher.getInstance("AES/ECB/NoPadding");
                _ecbAes.init(Cipher.ENCRYPT_MODE, _key);
            }
            catch (final NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
                // should not be thrown, we control the parameters
                throw new IllegalStateException(e);
            }
        }

        byte[] encryptECB(final byte[] input) {
            try {
                return _ecbAes.doFinal(input);
            }
            catch (final IllegalBlockSizeException | BadPaddingException e) {
                // should not be thrown, we control the parameters
                throw new IllegalStateException(e);
            }
        }

        byte[] encryptCBC(final byte[] input) {
            try {
                final byte[] cbc = _cbcMacAes.doFinal(input);
                // get the final 16 bytes of the AES output because of the prepended authentication tag
                return copyOfRange(cbc, cbc.length - 16, cbc.length);
            }
            catch (final IllegalBlockSizeException | BadPaddingException e) {
                // should not be thrown, we control the parameters
                throw new IllegalStateException(e);
            }
        }
    }
}
