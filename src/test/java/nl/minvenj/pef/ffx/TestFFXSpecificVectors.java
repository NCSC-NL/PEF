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

import static org.hamcrest.Matchers.equalToIgnoringCase;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class TestFFXSpecificVectors {

    @Parameter(0)
    public byte[] _key;

    @Parameter(1)
    public String _tweak;

    @Parameter(2)
    public int _radix;

    @Parameter(3)
    public String _input;

    @Parameter(4)
    public String _encrypted;

    @Parameters(name = "key: {0} - tweak: {1} - radix: {2} - input: {3} - encrypted: {4}")
    public static Object[][] data() throws DecoderException {
        final byte[] csrcKey = Hex.decodeHex("2b7e151628aed2a6abf7158809cf4f3c".toCharArray());
        return new Object[][]{
            // testing different key/tweak combinations
            {new byte[16], "00000000", 2, "00000000", "10010100"},
            {"q9yml3s5x4ds0f11".getBytes(), "FOOBAR", 36, "4D5D8GT15V1F58R5FP50", "R31MQ2D6538HT3087ISW"},
            {"0000000000000000".getBytes(), "}|>>?@)FOOBAZ:{#%^?", 20, "12FF9800", "00E45IC2"},
            {"0000000000065536".getBytes(), "4294967295", 10, "2147483647", "9115462938"},
            {"0000000000065536".getBytes(), "1231231231", 10, "2147483647", "9764557830"},

            // CSRC AES-FFX test vectors, in order, taken from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
            {csrcKey, "9876543210", 10, "0123456789", "6124200773"},
            {csrcKey, "", 10, "0123456789", "2433477484"},
            {csrcKey, "2718281828", 10, "314159", "535005"},
            {csrcKey, "7777777", 10, "999999999", "658229573"},
            {csrcKey, "TQF9J5QDAGSCSPB1", 36, "C4XPWULBM3M863JH", "C8AQ3U846ZWH6QZP"},

            // testing the smallest message size
            {csrcKey, "", 36, "pp", "ka"},
            {csrcKey, "", 10, "00", "68"},

            // testing large message sizes which trigger the padding function
            {csrcKey, "", 10, "999999999999999999999999999999999999999999999999999999999", "688163234659466867211819888439067584894842543433045957530"},
            {csrcKey, "", 36, "z02zx56erbt89y4y4pl1j0df0we56ef8yu1g15f1002r5r58y4y11f0d0", "5TTL8KYK63BGZL0GCCTSLM7HPTOPFQ33EUIGSSPWHFLH13VSO5VGAFUV8"},
            {csrcKey, "", 34, "xxxxxxxxxxxxxxxxxxxxbase36charactersoratleastalmostxxxxxxxxxxxxxxxxxxxx", "MLM6T6UUXHNB0FCJCTBLSDXFM676GOCPH7KIPHEABS2LEWEUCSAMRCGDQTF2A448MR9BU6D"},
            {csrcKey, "", 36, "X6WDO10DKNC0PI034VXBOGH0STQVN37VR7TAVIRYMY2KVR19NWJ45DR2DA9VN8JOFM16EVG4M7Y3206O916HQO0RXM0AWY1KURTHA7RL1IL73Q613ABKI2IGON9LUKXNAUFVX7FHBD6CCMDSMZ0VUKJXODGTGY1Y0NJ66ASNWPL9BWTWUKFJTMQJCI8CFR7REZ4Y3F3LJES7YSS2WCA6J6AKPYXP31JW4NYVPCPDRJBDYPQPC5R820LYUSAB896CY728II73DN47GKK4NVE8ABCFUK5NESDY78WX8TJYRU2N9ZJXZRAIUXTLZ4Z1JRKFO474H0IEB3BYZQWVQA5P4NUA269FBU3RWZU0WH62BA7R5V5ZIH46ZQGN6BDXVU46P4VHKJLDS7UNVREEDR7EZVCSSSKZPD2MVURM5P2OCZID6M5IIMRQC3235NRJ38ZWO7KMVZTCTGWDNL4OMMPQMYDOI0UH5NDTFI1DR81C9M6FS3T6I6VG",
                "V45HF9QP2LQMZ17OA6FMQEO8GIUTXWV8WWTLYP3INXLNFUGNGYTRBX8G8QD2MOR00DW0V9Z5HUT13X1VQNMYG0M0J4M7NPASF16ZMH7617JEI3QUF9F9M5K4A1WJKE516M4Q1I74WYMS4W3KWUMRAQD6PLVIWS4230F0QGZ2KTAKY95R9EGQDE0TO18U715JIT9R5ZM3N67MFZH3C0V0BVJ2TAITBA0M2TQR2WP1R36YG3G7JJT8VV55NTP861GTWWMXRN43FZQHKC0CW9S7KY3QX3J7QX1MR1ON1M58N111NOE11BXYNQBJPP7B2O99OJ8CUF9WPIX6SFVWAQKUFBC8UI5IRRSUU6GGZ0RCDPNWXD1OLK0GMZ7IJW13FIV2DR7KR3E3NRRTUYVM4UDQ7Q1PWUUG1SKMBC17BAYG3OSZVSWUKXOJM7GYHYUHC0VAAJJ1VT5YHR1QCWLMRX8CWWCG3B7VK22BTOKG0NI4OX8I7MDJMLJS"}
        };
    }

    @Test
    public void test() throws Exception {
        final FFX encrypter = new FFX(_key, _radix);

        final byte[] tweak = _tweak.getBytes();
        assertThat(encrypter.encrypt(tweak, _input), is(equalToIgnoringCase(_encrypted)));
        assertThat(encrypter.decrypt(tweak, _encrypted), is(equalToIgnoringCase(_input)));
    }
}
