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
package nl.minvenj.pef.pseudo.cli;

import static nl.minvenj.pef.util.TestUtil.assertEq;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import io.parsingdata.metal.data.ParseGraph;
import nl.minvenj.pef.Settings;
import nl.minvenj.pef.util.CLToolTestUtil;

@RunWith(Parameterized.class)
public class CLToolUnchangedIT {

    @ClassRule
    public static TemporaryFolder _tempFolder = new TemporaryFolder();

    @Parameter
    public String _fileName;

    @Parameters(name = "file: {0}")
    public static Iterable<? extends Object> data() {
        return Arrays.asList(
                             "1tcpdnsseg.pcap",
                             "1tcpdns.pcap",
                             "1tcpdnsaxfr.pcap",
                             "1udpssdp.pcap",
                             "1ipv6hopbyhophttp.pcap", // multiple extension headers
                             "1netflowipfixv10.pcap",
                             "1iptunneling.pcap",
                             "1db-lsp-disc.pcap",
                             "1snmp.pcap",
                             "1nat-pmp.pcap",
                             "dhcp_big_endian.pcapng",
                             "dhcp_little_endian.pcapng",
                             "many_interfaces_no_dns.pcapng"
        );
    }

    @Test
    public void assertUnchangedFileAfterProcessing() throws IOException {
        final String folder = _fileName.endsWith("pcap") ? "/pcaps" : "/pcapngs";
        final File preFile = new File(Settings.getTestBasePath() + folder, _fileName);
        final File postFile = _tempFolder.newFile();

        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getValues(preFile, postFile, CLToolTestUtil.PEF_COMMAND);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertEq(preValues, postValues);
    }

    @Test
    public void assertUnchangedPacketDataAfterProcessing() throws IOException {
        final String folder = _fileName.endsWith("pcap") ? "/pcaps" : "/pcapngs";
        final File preFile = new File(Settings.getTestBasePath() + folder, _fileName);
        final File postFile = _tempFolder.newFile();

        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getPacketValues(preFile, postFile, CLToolTestUtil.PEF_COMMAND);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertEq(preValues, postValues);
    }
}
