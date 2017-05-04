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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.equalToIgnoringCase;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import nl.minvenj.pef.util.Util;

@RunWith(Parameterized.class)
public class TestFFX {

    private static final SecureRandom RANDOM = new SecureRandom(new byte[]{(byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4});

    @Parameter(0)
    public FFXInput _ffxInput;

    @Parameter(1)
    public int _radix;

    @Parameter(2)
    public int _bound;

    @Parameters(name = "FFX input: {0} - radix: {1} - bound: {2}")
    public static Object[][] data() throws DecoderException {
        return new Object[][]{
            {new FFXInput(new byte[16], new byte[0]), 2, 512},
            {new FFXInput(new byte[16], new byte[0]), 21, 128},
            {new FFXInput(new byte[16], new byte[0]), 36, 64},

            {new FFXInput(new byte[16], new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9}), 13, 13000},
            {new FFXInput(new byte[16], new byte[]{(byte) 0xC1, 24}), 17, 1024},
            {new FFXInput(new byte[16], new byte[]{2}), 2, 1024},

            {new FFXInput(new byte[]{11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11}, new byte[]{(byte) 0F, 32}), 22, 640},
            {new FFXInput(new byte[]{(byte) 0xEF, 0x22, (byte) 0xA0, (byte) 0xA6, 0x79, 0x5D, (byte) 0xCC, 0x22, 0x12, (byte) 0xA1, 0x33, 0x12, (byte) 0xE9, 0x00, 0x10, 0x2E}, new byte[]{0, 0}), 2, 512},
            {new FFXInput(new byte[]{0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, (byte) 0x89, (byte) 0x9A, (byte) 0xAB, (byte) 0xBC, (byte) 0xCD, (byte) 0xDE, (byte) 0xEF, (byte) 0xF0}, new byte[0]), 2, 512},

            {new FFXInput(getRandomBytes(16), getRandomBytes(3)), 2, 512},
            {new FFXInput(getRandomBytes(16), getRandomBytes(7)), 3, 12345},
            {new FFXInput(getRandomBytes(16), getRandomBytes(0)), 17, 128},
            {new FFXInput(getRandomBytes(16), getRandomBytes(18)), 24, 64},
            {new FFXInput(getRandomBytes(16), getRandomBytes(2)), 31, 32}
        };
    }

    @Test
    public void testAllDifferentEncrypted() throws InvalidKeyException {
        final int messageSize = Integer.toString(_bound - 1, _radix).length();
        final FFX ffx = new FFX(_ffxInput.getKey(), _radix);

        final Map<String, String> mappings = new HashMap<>();
        for (int num = 0; num < _bound; num++) {
            final String input = Integer.toString(num, _radix);
            final String padded = Util.padZeroLeft(input, messageSize - input.length());
            mappings.put(padded, ffx.encrypt(_ffxInput.getTweak(), padded));
        }

        // each input should map on a different output
        assertThat(mappings.size(), is(equalTo(_bound)));

        int differences = 0;
        for (final Entry<String, String> entry : mappings.entrySet()) {
            if (!entry.getKey().equalsIgnoreCase(entry.getValue())) {
                differences++;
            }
        }

        // plain should differ from encrypted (most of the time)
        assertThat(differences, is(greaterThan(0)));
    }

    @Test
    public void testEncryptDecrypt() throws InvalidKeyException {
        final int messageSize = Integer.toString(_bound - 1, _radix).length();
        final FFX ffx = new FFX(_ffxInput.getKey(), _radix);

        for (int num = 0; num < _bound; num++) {
            final String input = Integer.toString(num, _radix);
            final String padded = Util.padZeroLeft(input, messageSize - input.length());
            final String encrypted = ffx.encrypt(_ffxInput.getTweak(), padded);
            final String decrypted = ffx.decrypt(_ffxInput.getTweak(), encrypted);

            // decrypted should be equal to original plain
            assertThat(decrypted, is(equalToIgnoringCase(padded)));
        }
    }

    private static byte[] getRandomBytes(final int size) {
        final byte[] bytes = new byte[size];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static class FFXInput {

        private final byte[] _key;
        private final byte[] _tweak;

        FFXInput(final byte[] key, final byte[] tweak) {
            super();
            _key = key;
            _tweak = tweak;
        }

        public byte[] getKey() {
            return _key;
        }

        public byte[] getTweak() {
            return _tweak;
        }

        @Override
        public String toString() {
            return String.format("[_key=%s, _tweak=%s]", Arrays.toString(_key), Arrays.toString(_tweak));
        }
    }
}
