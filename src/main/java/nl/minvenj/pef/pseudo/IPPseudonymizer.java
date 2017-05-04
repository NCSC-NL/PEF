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
package nl.minvenj.pef.pseudo;

import java.math.BigInteger;
import java.security.InvalidKeyException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import nl.minvenj.pef.ffx.FFX;
import nl.minvenj.pef.util.Util;

/**
 *  for IP addresses.
 *
 * It pseudonymizes based on a given key and a mask which determines the
 * bits to keep unchanged (and which not).
 *
 * For example, a mask of /24 on IP address 192.168.20.12 will pseudonymize to 192.168.20.x,
 * where x is the encrypted value. The mask number determines the amount of most significant bits
 * to be left untouched.
 *
 * @author Netherlands Forensic Institute.
 */
public final class IPPseudonymizer {

    private static final int IPV4_BIT_COUNT = 32;
    private static final int IPV6_BIT_COUNT = 128;

    private static final int RADIX = 2;
    private static final byte[] TWEAK = new byte[0];

    private final FFX _encrypter;
    private final int _bitCount;
    private final int _mask;
    private final int _changeBitCount;

    private IPPseudonymizer(final String key, final int mask, final int bitCount) throws InvalidKeyException {
        try {
            _encrypter = new FFX(Hex.decodeHex(key.toCharArray()), RADIX);
        }
        catch (final DecoderException e) {
            throw new InvalidKeyException(key);
        }
        _bitCount = bitCount;
        _mask = mask;
        _changeBitCount = bitCount - mask;
    }

    /**
     * Create a new  used for pseudonymizing IPv4 addresses.
     *
     * @param key the key to use for the encryption
     * @param mask the mask determining the bits to keep unchanged
     * @return an new IPPseudonymizer for IPv4 addresses
     * @throws InvalidKeyException if given key is invalid
     */
    public static IPPseudonymizer initIPv4Pseudonymizer(final String key, final int mask) throws InvalidKeyException {
        return new IPPseudonymizer(key, mask, IPV4_BIT_COUNT);
    }

    /**
     * Create a new  used for pseudonymizing IPv6 addresses.
     *
     * @param key the key to use for the encryption
     * @param mask the mask determining the bits to keep unchanged
     * @return an new IPPseudonymizer for IPv6 addresses
     * @throws InvalidKeyException if given key is invalid
     */
    public static IPPseudonymizer initIPv6Pseudonymizer(final String key, final int mask) throws InvalidKeyException {
        return new IPPseudonymizer(key, mask, IPV6_BIT_COUNT);
    }

    /**
     * Pseudonymizes given ip address.
     *
     * @param ip the bytes of the ip address
     * @return a byte array containing the pseudonymized ip address
     */
    public byte[] pseudonymize(final byte[] ip) {
        return pseudonymize(ip, _bitCount, _mask, _changeBitCount);
    }

    private byte[] pseudonymize(final byte[] ipAddress, final int bitCount, final int mask, final int changeBitCount) {
        final BigInteger ipBigInt = new BigInteger(1, ipAddress);
        final String ipString = ipBigInt.toString(RADIX);

        final BigInteger bigIntMask = BigInteger.ONE.shiftLeft(bitCount - mask).subtract(BigInteger.ONE);

        final String bitStringToEncrypt = ipBigInt.and(bigIntMask).toString(RADIX);
        final String bitStringToEncryptPadded = Util.padZeroLeft(bitStringToEncrypt, changeBitCount - bitStringToEncrypt.length());

        final String encrypted = _encrypter.encrypt(TWEAK, bitStringToEncryptPadded);

        final int keptBitCount = ipString.length() - changeBitCount;
        // keptBitCount is how many (string) bits to keep there are left in the original string
        // this is not necessarily equal to the mask, due to the conversion from BigInteger
        // since it will get converted to a number, take those left and concat, or if none, just use encrypted
        final String rebuiltBitString = keptBitCount > 0 ? ipString.substring(0, keptBitCount).concat(encrypted) : encrypted;

        return toIPAddressOfSize(new BigInteger(rebuiltBitString, RADIX), ipAddress.length);
    }

    private byte[] toIPAddressOfSize(final BigInteger bigInt, final int size) {
        final byte[] bytes = new byte[size];
        final byte[] intBytes = bigInt.toByteArray();

        if (size == intBytes.length) {
            System.arraycopy(intBytes, 0, bytes, 0, size);
        }
        else if (size < intBytes.length) {
            System.arraycopy(intBytes, intBytes.length - size, bytes, 0, size);
        }
        else {
            System.arraycopy(intBytes, 0, bytes, size - intBytes.length, intBytes.length);
        }
        return bytes;
    }
}
