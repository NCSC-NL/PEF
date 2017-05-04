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

public class CLToolTest {

    @ClassRule
    public static TemporaryFolder _tempFolder = new TemporaryFolder();

    private final String _basePath = Settings.getTestBasePath() + "/pcaps";

    @Test
    public void testChecksumParameter() throws IOException {
        final String command = "-4 30313233343536373839414243444546 /1 -c udp,ipv4";
        final Pair<ParseGraph, ParseGraph> values = CLToolTestUtil.getPacketValues(new File(_basePath + "/1udpdns.pcap"), _tempFolder.newFile(), command);

        final ParseGraph preValues = values.getLeft();
        final ParseGraph postValues = values.getRight();

        assertAddressesDiffer(preValues, postValues);

        assertEq(TestUtil.valueAtDepth(preValues, "headerchecksum", 0), new byte[]{(byte) 0xAC, (byte) 0x82});
        assertEq(TestUtil.valueAtDepth(postValues, "headerchecksum", 0), new byte[]{(byte) 0xAF, 0x22});

        assertEq(TestUtil.valueAtDepth(preValues, "udpchecksum", 0), new byte[]{0x7C, 0x15});
        assertEq(TestUtil.valueAtDepth(postValues, "udpchecksum", 0), new byte[]{0x7E, (byte) 0xB5});
    }
}
