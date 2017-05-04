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
package nl.minvenj.pef.util;

import java.io.IOException;
import java.nio.ByteOrder;
import java.util.Collection;
import java.util.Locale;

import io.parsingdata.metal.data.ByteStream;
import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.encoding.Encoding;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.metal.stream.ArrayByteStream;

/**
 * Utility class containing useful methods.
 *
 * @author Netherlands Forensic Institute.
 */
public final class Util {

    // cache of '0' strings used for padding
    private static final String[] CACHED_PREPS = new String[128];

    static {
        for (int i = 0; i < CACHED_PREPS.length; i++) {
            final char[] prepend = new char[i];
            for (int j = 0; j < i; j++) {
                prepend[j] = '0';
            }
            CACHED_PREPS[i] = new String(prepend);
        }
    }

    private Util() {
    }

    /**
     * Pad a number of '0' characters to the left side of a string.
     *
     * @param string the string to pad
     * @param count the amount of characters to pad
     *
     * @return a string left padded count times with '0'
     */

    public static String padZeroLeft(final String string, final int count) {
        if (count <= 0) {
            return string;
        }
        if (count < CACHED_PREPS.length) {
            return CACHED_PREPS[count].concat(string);
        }
        final char[] prepend = new char[count];
        for (int i = 0; i < prepend.length; i++) {
            prepend[i] = '0';
        }
        return new String(prepend).concat(string);
    }

    /**
     * Merge a list of byte arrays.
     *
     * @param pieces the byte arrays to merge
     * @return a single byte array created from concatenating the individual byte arrays
     */
    public static byte[] mergeBytes(final Collection<byte[]> pieces) {
        int length = 0;
        int offset = 0;
        for (final byte[] piece : pieces) {
            length += piece.length;
        }
        final byte[] merged = new byte[length];
        for (final byte[] piece : pieces) {
            System.arraycopy(piece, 0, merged, offset, piece.length);
            offset += piece.length;
        }
        return merged;
    }

    /**
     * This method can be used for argument checking for null, with a named
     * argument for logging purposes.
     *
     * Stolen from Hansken :)
     *
     * @param argName the name of the argument
     * @param <T> the value to assign
     * @param arg the argument to null-check
     * @return the argument that is null-checked
     * @throws IllegalArgumentException when argument is null
     */
    public static <T> T argNotNull(final String argName, final T arg) {
        if (arg == null) {
            throw new IllegalArgumentException(String.format(Locale.ROOT, "Argument '%s' cannot be null!", argName));
        }
        return arg;
    }

    /**
     * Convert a byte to its unsigned value.
     *
     * @param b the byte to convert
     * @return an integer containing the bits of the given byte, as an unsigned value
     */
    public static int toUnsignedInt(final byte b) {
        return b & 0xFF;
    }

    /**
     * Convert an unsigned short int to a byte array (size 2).
     *
     * @param unsignedShort value stored as int (Java does not support unsigned short)
     * @param order the ordering of the byte array to be returned
     * @return byte array
     * @throws IllegalArgumentException on insertion of an int not within bounds of a short value
     */
    public static byte[] unsignedShortToByteArray(final int unsignedShort, ByteOrder order) {
        if (unsignedShort < 0 || unsignedShort > 65535 ) {
            throw new IllegalArgumentException("Unsigned short can not be negative or larger than 65535");
        }
        if (order == ByteOrder.BIG_ENDIAN){
            return new byte[]{(byte) (unsignedShort >>> 8), (byte) (unsignedShort & 0xFF)};
        }
        else {
            return new byte[] {(byte) (unsignedShort & 0xFF), (byte) (unsignedShort >>> 8)};
        }
    }

    /**
     * Parses InputData data with given format.
     *
     * @param source the data to parse from
     * @param format the format to parse with
     * @return a {@link ParseResult}
     * @throws IOException whenever {@link Token#parse(Environment, Encoding)} throws one
     */
    public static ParseResult parse(final ByteStream source, final Token format) throws IOException {
        return parse(source, 0, format);
    }

    /**
     * Parses InputData data from given offset, with given format.
     *
     * @param source the data to parse from
     * @param offset the offset to start parsing from
     * @param format the format to parse with
     * @return a {@link ParseResult}
     * @throws IOException whenever {@link Token#parse(Environment, Encoding)} throws one
     */
    public static ParseResult parse(final ByteStream source, final long offset, final Token format) throws IOException {
        return parse(source, offset, format, new Encoding());
    }

    /**
     * Parses an array of bytes with given format.
     *
     * @param source the byte array to parse
     * @param format the format to parse with
     * @return a {@link ParseResult}
     * @throws IOException whenever {@link Token#parse(Environment, Encoding)} throws one
     */
    public static ParseResult parse(final byte[] source, final Token format) throws IOException {
        return parse(new ArrayByteStream(source), 0L, format, new Encoding());
    }

    /**
     * Parses InputData data from given offset, with given format.
     *
     * @param source the data to parse from
     * @param offset the offset to start parsing from
     * @param format the format to parse with
     * @param encoding the encoding to interpret the data in
     * @return a {@link ParseResult}
     * @throws IOException whenever {@link Token#parse(Environment, Encoding)} throws one
     */
    public static ParseResult parse(final ByteStream source, final long offset, final Token format, final Encoding encoding) throws IOException {
        final Environment environment = new Environment(source, offset);
        return format.parse(environment, encoding);
    }

    /**
     * Convert a varag list of tokens to an array of tokens.
     *
     * @param tokens the tokens to convert
     * @return an array containing the tokens
     */
    public static Token[] tokens(final Token... tokens) {
        return tokens;
    }

    /**
     * Concatenate a series of byte arrays.
     *
     * @param byteArrays the arrays to concatenate
     *
     * @return a single byte array created by concatenating all given arrays in order
     */
    public static byte[] concatBytes(final byte[]... byteArrays) {
        int length = 0;
        for (final byte[] bytes : byteArrays) {
            length += bytes.length;
        }

        int offset = 0;
        final byte[] merged = new byte[length];
        for (final byte[] bytes : byteArrays) {
            System.arraycopy(bytes, 0, merged, offset, bytes.length);
            offset += bytes.length;
        }
        return merged;
    }

    /**
     * Perform modulo taking the sign of the divider, where the divider is always positive.
     *
     * @param l dividend
     * @param r divider
     * @return dividend mod divider
     */
    public static int modPosDiv(final int l, final int r) {
        if (r < 0) {
            throw new IllegalArgumentException("divider must be a positive number: " + r);
        }
        final int rem = l % r;
        return rem >= 0 ? rem : r + rem;
    }

    /**
     * Check if a value is even.
     *
     * @param val the value to check
     *
     * @return true if given value is even
     */
    public static boolean even(final int val) {
        return (val & 1) == 0;
    }

    /**
     * Check if a string can be parsed as a number in a given base.
     *
     * @param string input string to check
     * @param radix the radix to check for
     * @return true if the string represents a number in base radix
     */
    public static boolean stringNumInRadix(final String string, final int radix) {
        for (final char c : string.toCharArray()) {
            if (Character.digit(c, radix) == -1) {
                return false;
            }
        }
        return true;
    }
}
