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
package nl.minvenj.pef.pseudo.dump.cap.pcapng;

import static nl.minvenj.pef.util.CLToolTestUtil.getValuesFromDumpFile;
import static nl.minvenj.pef.util.CLToolTestUtil.runWithCommand;
import static nl.minvenj.pef.util.TestUtil.assertEq;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

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
public class TestPCAPNGThreading {

    @ClassRule
    public static TemporaryFolder _tempFolder = new TemporaryFolder();

    @Parameter
    public String _fileName;

    private final String _testBasePath = Settings.getTestBasePath() + "/pcapngs";

    @Parameters(name = "file: {0}")
    public static Iterable<? extends Object> data() {
        return Arrays.asList(
                             "test008.ntar",
                             "many_interfaces.pcapng",
                             "many_interfaces_no_dns.pcapng",
                             "dhcp_little_endian.pcapng",
                             "dhcp_big_endian.pcapng",
                             "1udpdns.pcapng");
    }

    @Test
    public void assertSameFileAfterAnyModeOfProcessing() throws IOException {
        final File preFile = new File(_testBasePath, _fileName);

        final File postFileSingleThread = _tempFolder.newFile();
        final File postFileMultiThread = _tempFolder.newFile();

        runWithCommand(preFile, postFileSingleThread, CLToolTestUtil.PEF_COMMAND);
        runWithCommand(preFile, postFileMultiThread, CLToolTestUtil.PEF_COMMAND + " -m 4");

        final ParseGraph singleThreadValues = getValuesFromDumpFile(postFileSingleThread);
        final ParseGraph multiThreadValuesValues = getValuesFromDumpFile(postFileMultiThread);

        assertEq(singleThreadValues, multiThreadValuesValues);
    }
}
