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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import java.security.InvalidKeyException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

public class IPPseudonymizerTest {

    @Test
    public void testIPv4Mask2() throws InvalidKeyException {
        final IPPseudonymizer ipv4Pseudonymizer = IPPseudonymizer.initIPv4Pseudonymizer("0123465789ABCDEF0123456789ABCDEF", 2);
        final byte[] ip = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0XFF};

        final byte[] newIp = ipv4Pseudonymizer.pseudonymize(ip.clone());

        assertThat(newIp[0] & 0xC0, is(equalTo(ip[0] & 0xC0)));

        assertThat(newIp[0] & 0x3F, is(not(equalTo(ip[0] & 0x3F))));
        assertThat(newIp[1], is(not(equalTo(ip[1]))));
        assertThat(newIp[2], is(not(equalTo(ip[2]))));
        assertThat(newIp[3], is(not(equalTo(ip[3]))));
    }

    @Test
    public void testIPv4Mask17() throws InvalidKeyException {
        final IPPseudonymizer ipv4Pseudonymizer = IPPseudonymizer.initIPv4Pseudonymizer("7ED73EB6A78E8615EE718B27559E285F", 17);
        final byte[] ip = new byte[]{0x12, 0x34, 0x56, 0X78};

        final byte[] newIp = ipv4Pseudonymizer.pseudonymize(ip.clone());

        assertThat(newIp[0], is(equalTo(ip[0])));
        assertThat(newIp[1], is(equalTo(ip[1])));
        assertThat(newIp[2] & 0x80, is(equalTo(ip[2] & 0x80)));

        assertThat(newIp[2] & 0x7F, is(not(equalTo(ip[2] & 0x7F))));
        assertThat(newIp[3], is(not(equalTo(ip[3]))));
    }

    @Test
    public void testIPv4Mask24() throws InvalidKeyException {
        final IPPseudonymizer ipv4Pseudonymizer = IPPseudonymizer.initIPv4Pseudonymizer("3AE1E5F99DD4FF7196FE64ACDE688C89", 24);
        final byte[] ip = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0XFF};

        final byte[] newIp = ipv4Pseudonymizer.pseudonymize(ip.clone());

        assertThat(newIp[0], is(equalTo(ip[0])));
        assertThat(newIp[1], is(equalTo(ip[1])));
        assertThat(newIp[2], is(equalTo(ip[2])));

        assertThat(newIp[3], is(not(equalTo(ip[3]))));
    }

    @Test
    public void testIPv6Mask9() throws InvalidKeyException, DecoderException {
        final int mask = 9;
        final IPPseudonymizer ipv6Pseudonymizer = IPPseudonymizer.initIPv6Pseudonymizer("3AE1E5F99DD4FF7196FE64ACDE688C89", mask);
        final byte[] ip = Hex.decodeHex("123465a4d5f4e55511bb96a864a01201".toCharArray());

        final byte[] newIp = ipv6Pseudonymizer.pseudonymize(ip.clone());

        assertThat(newIp[0], is(equalTo(ip[0])));
        assertThat(newIp[1] & 0b1000, is(equalTo(ip[1] & 0b1000)));

        for (int i = mask / 8; i < 16; i++) {
            assertThat(newIp[i], is(not(equalTo(ip[i]))));
        }
    }

    @Test
    public void testIPv6Mask48() throws InvalidKeyException, DecoderException {
        final int mask = 48;
        final IPPseudonymizer ipv6Pseudonymizer = IPPseudonymizer.initIPv6Pseudonymizer("3AE1E5F99DD4FA894D45D6FFDE688EE0", mask);
        final byte[] ip = Hex.decodeHex("fd7376ae803033ddb942d98a864e8743".toCharArray());

        final byte[] newIp = ipv6Pseudonymizer.pseudonymize(ip.clone());

        for (int i = 0; i < mask / 8; i++) {
            assertThat(newIp[i], is(equalTo(ip[i])));
        }

        for (int i = mask / 8; i < 16; i++) {
            assertThat(newIp[i], is(not(equalTo(ip[i]))));
        }
    }

    @Test
    public void testIPv6Mask120() throws InvalidKeyException, DecoderException {
        final int mask = 120;
        final IPPseudonymizer ipv6Pseudonymizer = IPPseudonymizer.initIPv6Pseudonymizer("3AE1E5F99DD4FF7196FE64ACDE688C89", mask);
        final byte[] ip = Hex.decodeHex("97010a9b423def694d2aa231011d1210".toCharArray());

        final byte[] newIp = ipv6Pseudonymizer.pseudonymize(ip.clone());

        for (int i = 0; i < mask / 8; i++) {
            assertThat(newIp[i], is(equalTo(ip[i])));
        }

        for (int i = mask / 8; i < 16; i++) {
            assertThat(newIp[i], is(not(equalTo(ip[i]))));
        }
    }
}
