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
package nl.minvenj.pef.stream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * End-to-end test for live stream pseudonymization.
 * @author Netherlands Forensic Institute.
 */
public class LiveCaptureTest {
    @Ignore("This interface does not exist anymore")
    @Test
    public void testPerformanceMetal() {
        final String[] cmd = String.format("-4 30313233343536373839414243444546 /16 -c all metal %s",
                Paths.get(".").toAbsolutePath().normalize().toString()).split(" ");
        LiveCapture.main(cmd);
    }

    @Ignore("This interface does not exist anymore")
    @Test
    public void testPerformanceJNetPcap() {
        final String[] cmd = String.format("-4 30313233343536373839414243444546 /16 jnetpcap -c all %s",
                Paths.get(".").toAbsolutePath().normalize().toString()).split(" ");
        LiveCapture.main(cmd);
    }

    @Ignore("This interface does not exist anymore")
    @Test
    public void compareOutputJNetPcapMetal() throws IOException{
        // Create a dumper using both the libraries. Wrapper around the others.
        final String[] cmd = String.format("-4 30313233343536373839414243444546 /16 test -c all %s",
            Paths.get(".").toAbsolutePath().normalize().toString()).split(" ");
        LiveCapture.main(cmd);
        final File metalFile = new File("metal-test.pcap");
        final File jnetpcapFile = new File("jnetpcap-test.pcap");
        //There is not test for comparing with the reference file because if no DNS was found
        // no packets have been modified.
        final File referenceFile = new File("reference");

        Assert.assertTrue("The files should be identical!", FileUtils.contentEquals(metalFile, jnetpcapFile));

        // Temporary cleanup.
        if (metalFile.exists()) {
            metalFile.delete();
        }
        if (jnetpcapFile.exists()) {
            jnetpcapFile.delete();
        }
        if (referenceFile.exists()) {
            referenceFile.delete();
        }
    }
}
