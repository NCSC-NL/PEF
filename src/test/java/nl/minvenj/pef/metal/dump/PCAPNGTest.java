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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import io.parsingdata.metal.data.ByteStream;
import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.data.ParseValueList;
import io.parsingdata.metal.data.selection.ByName;
import io.parsingdata.metal.encoding.Encoding;
import nl.minvenj.pef.Settings;
import nl.minvenj.pef.util.InMemoryByteStream;

@RunWith(Parameterized.class)
public class PCAPNGTest {

    private final Encoding _encoding = new Encoding();

    @Parameter(0)
    public String _file;

    @Parameter(1)
    public long _shbCount;

    @Parameter(2)
    public long _idbCount;

    @Parameter(3)
    public long _blocks;

    @Parameters(name = "file: {0} - SHB: {1} - IDB: {2} - blocks: {3}")
    public static Object[][] data() {
        return new Object[][]{
            {"test008.ntar", 2, 2, 4},
            {"many_interfaces.pcapng", 1, 11, 88},
            {"many_interfaces_no_dns.pcapng", 1, 11, 73},
            {"dhcp_little_endian.pcapng", 1, 1, 7},
            {"dhcp_big_endian.pcapng", 1, 1, 7},
            {"1udpdns.pcapng", 1, 1, 3}
        };
    }

    @Test
    public void test() throws IOException {
        final byte[] data = Files.readAllBytes(Paths.get(Settings.getTestBasePath(), "pcapngs", _file));
        final ByteStream stream = new InMemoryByteStream(data);
        final Environment environment = new Environment(stream);
        final ParseResult result = PCAPNG.FORMAT.parse(environment, _encoding);

        assertTrue(result.succeeded);
        assertEquals(data.length, result.environment.offset);

        final ParseGraph graph = result.environment.order;
        final ParseValueList blockTypeList = ByName.getAllValues(graph, "type");

        assertThat(blockTypeList.size, is(equalTo(_blocks)));
        assertThat(filteredSize(blockTypeList, 0x0A0D0D0A), is(equalTo(_shbCount)));
        assertThat(filteredSize(blockTypeList, 0x00000001), is(equalTo(_idbCount)));
    }

    private long filteredSize(final ParseValueList list, final int value) {
        if (list.head == null) {
            return 0;
        }
        // TODO The Good, the Bad and the Ternary?
        return (list.head.asNumeric().intValue() == value ? 1 : 0) + filteredSize(list.tail, value);
    }
}
