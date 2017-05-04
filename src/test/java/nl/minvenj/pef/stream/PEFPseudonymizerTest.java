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
import java.security.InvalidKeyException;

import org.apache.commons.io.FileUtils;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.junit.Assert;
import org.junit.Test;

import nl.minvenj.pef.Settings;
import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.pseudo.cli.FramePseudonymizerBuilder;

/**
 * Test for the live stream pseudonymization with metal
 * @author Netherlands Forensic Institute.
 */
public class PEFPseudonymizerTest {
    final private String _testdir = Settings.getTestBasePath() + "/pcaps";

    @Test
    public void dumpFiles() throws IOException, InvalidKeyException {
        final StringBuilder errbuf = new StringBuilder(); // For any error msgs
        final String file = _testdir + File.separator + "56packets.pcap";
        final Pcap pcap = Pcap.openOffline(file, errbuf);

        PcapPacketHandler<PseudoPacketHandler> dumpHandler = new PcapPacketHandler<PseudoPacketHandler>() {
            public void nextPacket(PcapPacket packet, PseudoPacketHandler handler) {
                handler.handle(packet);
            }
        };

        if (pcap == null) {
            System.out.printf("Error while opening device for capture: "
                    + errbuf.toString());
        }

        final FramePseudonymizerBuilder builder = new FramePseudonymizerBuilder();
        builder.pseudoIPv4("30313233343536373839414243444546", 16);
        final FramePseudonymizer pseudonymizer = builder.build();
        final String destination = "pseudo-capture-file.cap";
        final PEFPseudonymizeDumper pseudonymizeDumper = new PEFPseudonymizeDumper(pcap, destination, pseudonymizer);

        pcap.loop(56, dumpHandler, pseudonymizeDumper);

        pseudonymizeDumper.close();
        pcap.close();
        Assert.assertFalse("The files are not identical!", FileUtils.contentEquals(new File(file), new File(destination)));
    }
}
