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
package nl.minvenj.pef.metal.dump;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Test;

import io.parsingdata.metal.data.ByteStream;
import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.encoding.Encoding;
import nl.minvenj.pef.Settings;
import nl.minvenj.pef.util.InMemoryByteStream;

public class PCAPTest {

    private final Encoding _encoding = new Encoding();

    @Test
    public void testIdentical() throws IOException {
        test("1dnsidentical.pcap");
    }

    @Test
    public void testSwapped() throws IOException {
        test("1dnsswapped.pcap");
    }

    private void test(final String path) throws IOException {
        final byte[] data = Files.readAllBytes(Paths.get(Settings.getTestBasePath(), "pcaps", path));
        final ByteStream stream = new InMemoryByteStream(data);
        final Environment environment = new Environment(stream);
        final ParseResult result = PCAP.FORMAT.parse(environment, _encoding);

        assertTrue(result.succeeded);
        assertEquals(data.length, result.environment.offset);
    }
}
