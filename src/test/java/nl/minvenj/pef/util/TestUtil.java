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

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.Range;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;

import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.data.ParseValueList;
import io.parsingdata.metal.data.selection.ByName;

public class TestUtil {

    public static Range<Long> range(final long fromInclusive, final long toInclusive) {
        return Range.between(fromInclusive, toInclusive);
    }

    @SafeVarargs
    public static List<Range<Long>> ranges(final Range<Long>... ranges) {
        return Arrays.asList(ranges);
    }

    /** Get a value with given name at a given depth. (0-based index) */
    public static ParseValue valueAtDepth(final ParseGraph values, final String name, final int depth) {
        ParseValueList all = ByName.getAllValues(values, name);
        for (int i = 0; i < depth && all.head != null; i++) {
            all = all.tail;
        }
        return all.head;
    }

    /**
     * Convert a String of bytes to a byte array.
     *
     * @param hexString the string in hex format (e.g. "E5D34F")
     * @return a byte array containing the bytes represented by the String characters
     * @throws IllegalArgumentException thrown if an odd number or illegal of characters is supplied
     */
    public static byte[] hexStringToBytes(final String hexString) {
        try {
            return Hex.decodeHex(hexString.toCharArray());
        }
        catch (final DecoderException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Convert an array of bytes representing an IPv4/6 address to a dotted decimal or colonized format respectively.
     *
     * @param ipBytes the bytes containing the IP data
     * @return a string represenation of IPv4/6
     */
    public static String ipStringFromBytes(final byte[] ipBytes) {
        try {
            return InetAddress.getByAddress(ipBytes).getHostAddress();
        }
        catch (final UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Convert an integer representing an IPv4 address to its dotted decimal format.
     *
     * @param ip the int containing the IP data
     * @return a dotted decimal IPv4 String
     */
    public static String ipv4StringFromInt(final int ip) {
        try {
            final byte[] ipBytes = ByteBuffer.allocate(4).putInt(ip).array();
            final InetAddress foo = InetAddress.getByAddress(ipBytes);
            return foo.getHostAddress();
        }
        catch (final UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static Matcher<ParseValue> equalTo(final ParseValue parseValue) {
        return new BaseMatcher<ParseValue>() {
            @Override
            public boolean matches(final Object o) {
                if (parseValue == o) {
                    return true;
                }
                if (o == null || parseValue.getClass() != o.getClass()) {
                    return false;
                }
                final ParseValue that = (ParseValue) o;
                return parseValue.offset == that.offset && Objects.equals(parseValue.name, that.name) && Objects.equals(parseValue.definition, that.definition) && Arrays.equals(parseValue.getValue(), that.getValue());
            }

            @Override
            public void describeTo(final Description description) {
                description.appendValue(parseValue);
            }
        };
    }

    public static void assertEq(final ParseValue value, final byte[] bytes) {
        assertThat(value.getValue(), is(Matchers.equalTo(bytes)));
    }

    public static void assertNeq(final ParseValue oneValue, final ParseValue otherValue) {
        assertThat(oneValue, is(not(equalTo(otherValue))));
    }

    public static void assertEq(final ParseGraph preValues, final ParseGraph postValues) {
        assertThat(preValues.size, is(Matchers.equalTo(postValues.size)));
        assertThat(preValues.getDefinition(), is(Matchers.equalTo(postValues.getDefinition())));

        if (preValues == ParseGraph.EMPTY) {
            assertThat(postValues, is(Matchers.equalTo(ParseGraph.EMPTY)));
            return;
        }
        if (preValues.head.isValue()) {
            assertThat(preValues.head.asValue(), is(equalTo(postValues.head.asValue())));
        }
        if (preValues.head.isGraph()) {
            assertEq(preValues.head.asGraph(), postValues.head.asGraph());
        }
        if (preValues.head.isRef()) {
            assertThat(preValues.head.asRef().location, is(Matchers.equalTo(postValues.head.asRef().location)));
            return;
        }
        assertEq(preValues.tail, postValues.tail);
    }

    /** Assert that all IP addresses have been changed. */
    public static void assertAddressesDiffer(final ParseGraph preValues, final ParseGraph postValues) {
        int depth = 0;
        boolean foundSomething = true;

        while (foundSomething) {
            foundSomething = false;

            final ParseValue ipSource = TestUtil.valueAtDepth(preValues, "ipsource", depth); // found IPv4 source address
            if (ipSource != null) {
                foundSomething = true;
                assertNeq(ipSource, TestUtil.valueAtDepth(postValues, "ipsource", depth));
                assertNeq(TestUtil.valueAtDepth(preValues, "ipdestination", depth), TestUtil.valueAtDepth(postValues, "ipdestination", depth));
            }

            final ParseValue sourceAddress = TestUtil.valueAtDepth(preValues, "sourceaddress", depth); // found IPv6 source address
            if (sourceAddress != null) {
                foundSomething = true;
                assertNeq(sourceAddress, TestUtil.valueAtDepth(postValues, "sourceaddress", depth));
                assertNeq(TestUtil.valueAtDepth(preValues, "destinationaddress", depth), TestUtil.valueAtDepth(postValues, "destinationaddress", depth));
            }

            depth++;
        }
    }

    public static String hex(final byte[] data) {
        return Hex.encodeHexString(data).toUpperCase();
    }
}
