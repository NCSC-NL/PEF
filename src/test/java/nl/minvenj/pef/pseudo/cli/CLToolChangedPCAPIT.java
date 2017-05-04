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

import static nl.minvenj.pef.util.TestUtil.assertAddressesDiffer;
import static nl.minvenj.pef.util.TestUtil.assertEq;

import java.io.File;
import java.io.IOException;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import io.parsingdata.metal.data.ParseGraph;
import nl.minvenj.pef.Settings;
import nl.minvenj.pef.util.CLToolTestUtil;
import nl.minvenj.pef.util.TestUtil;

public class CLToolChangedPCAPIT {

    @ClassRule
    public static TemporaryFolder _tempFolder = new TemporaryFolder();

    private final String _basePath = Settings.getTestBasePath() + "/pcaps";

    // checksum calculations are validated with Wireshark

    @Test
    public void testUDPDNS1() throws IOException {
        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getPacketValues(new File(_basePath + "/1udpdns.pcap"), _tempFolder.newFile(), CLToolTestUtil.PEF_COMMAND);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertAddressesDiffer(preValues, postValues);

        assertEq(TestUtil.valueAtDepth(preValues, "headerchecksum", 0), new byte[]{(byte) 0xAC, (byte) 0x82});
        assertEq(TestUtil.valueAtDepth(postValues, "headerchecksum", 0), new byte[]{0x6D, (byte) 0xD5});

        assertEq(TestUtil.valueAtDepth(preValues, "udpchecksum", 0), new byte[]{0x7C, 0x15});
        assertEq(TestUtil.valueAtDepth(postValues, "udpchecksum", 0), new byte[]{0x3D, 0x68});
    }

    @Test
    public void testUDPDNS2() throws IOException {
        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getPacketValues(new File(_basePath + "/1udpdns2.pcap"), _tempFolder.newFile(), CLToolTestUtil.PEF_COMMAND);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertAddressesDiffer(preValues, postValues);

        assertEq(TestUtil.valueAtDepth(preValues, "headerchecksum", 0), new byte[]{(byte) 0x85, (byte) 0xC2});
        assertEq(TestUtil.valueAtDepth(postValues, "headerchecksum", 0), new byte[]{0x05, 0x56});

        assertEq(TestUtil.valueAtDepth(preValues, "udpchecksum", 0), new byte[]{0x54, 0x03});
        assertEq(TestUtil.valueAtDepth(postValues, "udpchecksum", 0), new byte[]{(byte) 0xD3, (byte) 0x96});
    }

    @Test
    public void testUDPDNSSEC() throws IOException {
        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getPacketValues(new File(_basePath + "/1udpdnssec.pcap"), _tempFolder.newFile(), CLToolTestUtil.PEF_COMMAND);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertAddressesDiffer(preValues, postValues);

        assertEq(TestUtil.valueAtDepth(preValues, "headerchecksum", 0), new byte[]{(byte) 0xFE, 0x2D});
        assertEq(TestUtil.valueAtDepth(postValues, "headerchecksum", 0), new byte[]{0x63, (byte) 0x80});

        assertEq(TestUtil.valueAtDepth(preValues, "udpchecksum", 0), new byte[]{0x28, 0x5B});
        assertEq(TestUtil.valueAtDepth(postValues, "udpchecksum", 0), new byte[]{(byte) 0x8D, (byte) 0xAD});
    }

    @Test
    public void testUDPMDNS() throws IOException {
        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getPacketValues(new File(_basePath + "/1udpmdns.pcap"), _tempFolder.newFile(), CLToolTestUtil.PEF_COMMAND);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertAddressesDiffer(preValues, postValues);

        assertEq(TestUtil.valueAtDepth(preValues, "headerchecksum", 0), new byte[]{0x55, (byte) 0xED});
        assertEq(TestUtil.valueAtDepth(postValues, "headerchecksum", 0), new byte[]{(byte) 0xDF, (byte) 0x99});

        assertEq(TestUtil.valueAtDepth(preValues, "udpchecksum", 0), new byte[]{(byte) 0x99, 0x7C});
        assertEq(TestUtil.valueAtDepth(postValues, "udpchecksum", 0), new byte[]{0x23, 0x29});
    }

    @Test
    public void testUDPNBNS() throws IOException {
        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getPacketValues(new File(_basePath + "/1udpnbns.pcap"), _tempFolder.newFile(), CLToolTestUtil.PEF_COMMAND);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertAddressesDiffer(preValues, postValues);

        assertEq(TestUtil.valueAtDepth(preValues, "headerchecksum", 0), new byte[]{(byte) 0xFA, (byte) 0xEB});
        assertEq(TestUtil.valueAtDepth(postValues, "headerchecksum", 0), new byte[]{(byte) 0xC3, (byte) 0xD3});

        assertEq(TestUtil.valueAtDepth(preValues, "udpchecksum", 0), new byte[]{0x69, 0x55});
        assertEq(TestUtil.valueAtDepth(postValues, "udpchecksum", 0), new byte[]{0x32, 0x3D});
    }

    @Test // TODO PEF-43: what with bad original checksums? (if caused by offloading == packet is sent from host?)
    public void testUDPLLMNRWithBadChecksum() throws IOException {
        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getPacketValues(new File(_basePath + "/1udpllmnrbadchecksum.pcap"), _tempFolder.newFile(), CLToolTestUtil.PEF_COMMAND);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertAddressesDiffer(preValues, postValues);

        assertEq(TestUtil.valueAtDepth(preValues, "headerchecksum", 0), new byte[]{0x1C, 0x0A});
        assertEq(TestUtil.valueAtDepth(postValues, "headerchecksum", 0), new byte[]{(byte) 0xFA, (byte) 0x73});

        assertEq(TestUtil.valueAtDepth(preValues, "udpchecksum", 0), new byte[]{(byte) 0x8A, 0x78}); // bad checksum, should be 0xFCE7 according to Wireshark
        assertEq(TestUtil.valueAtDepth(postValues, "udpchecksum", 0), new byte[]{(byte) 0xDB, 0x51});
    }

    @Test
    public void testIPv6UDPLLMNR() throws IOException {
        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getPacketValues(new File(_basePath + "/1ipv6udpllmnr.pcap"), _tempFolder.newFile(), CLToolTestUtil.PEF_COMMAND);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertAddressesDiffer(preValues, postValues);

        assertEq(TestUtil.valueAtDepth(preValues, "udpchecksum", 0), new byte[]{(byte) 0x4F, (byte) 0x84});
        assertEq(TestUtil.valueAtDepth(postValues, "udpchecksum", 0), new byte[]{(byte) 0xD2, 0x0C});
    }

    @Test
    public void testIPv6UDPMDNS() throws IOException {
        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getPacketValues(new File(_basePath + "/1ipv6udpmdns.pcap"), _tempFolder.newFile(), CLToolTestUtil.PEF_COMMAND);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertAddressesDiffer(preValues, postValues);

        assertEq(TestUtil.valueAtDepth(preValues, "udpchecksum", 0), new byte[]{0x24, 0x10});
        assertEq(TestUtil.valueAtDepth(postValues, "udpchecksum", 0), new byte[]{(byte) 0x6A, (byte) 0x05});
    }

}
