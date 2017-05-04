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
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.JProtocol;

import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.pseudo.IPPseudonymizer;
/**
 * TestPseudonymizerLibs is added to provide users an end-to-end test and check the functionality
 * on their own stream. Each packet captured from the stream will be handled and pseudonymized by the metal and jnetpcap library.
 * A reference file is stored to provide insight in the original stream.
 *
 * @author Netherlands Forensic Institute.
 */
public class TestPseudonymizerLibs implements PseudoPacketHandler{
    private static final Logger logger = Logger.getLogger(LiveCapture.class.getName());
    private final PcapDumper _metalDumper, _jnetpcapDumper, _referenceDumper;
    private final JNetPcapPacketModifier _packetModifier;
    private final FramePseudonymizer _pseudonymizer;

    /**
     * Constructor for the testlibrary. Contains the configurations for both the libraries.
     *
     * @param pcap the interface with the pcap (libpcap) library
     * @param destinationDir the directory where the files will be stored
     * @param pseudonymizerMap mapping of ip type and pseudonymizer to be used
     * @param checksumList the list of protocols for which the checksum must be recalculated
     * @param pseudonymizer the frame pseuddonymizer for the metal library
     */
    TestPseudonymizerLibs(final Pcap pcap, final String destinationDir, final Map<JProtocol, IPPseudonymizer> pseudonymizerMap,
                    final List<Integer> checksumList, final FramePseudonymizer pseudonymizer) {
        _packetModifier = new JNetPcapPacketModifier(pseudonymizerMap, checksumList, true);
        _pseudonymizer = pseudonymizer;

        _referenceDumper = pcap.dumpOpen(destinationDir + File.separator + "reference.pcap");
        _jnetpcapDumper = pcap.dumpOpen(destinationDir + File.separator + "jnetpcap-test.pcap");
        _metalDumper = pcap.dumpOpen(destinationDir + File.separator + "metal-test.pcap");
    }

    /**
     * Handles the packets and writes the packet after modification with the metal library,
     * JNetPcap library and stores a reference file.
     *
     * @param packet the captured PcapPacket
     */
    @Override
    public void handle(PcapPacket packet) {
        _referenceDumper.dump(packet);

        byte[] packetData = packet.getByteArray(0, packet.size());
        try {
            final byte[] pseudopacketData  = _pseudonymizer.pseudonymize(packetData);
            PcapPacket copyPacket = new PcapPacket(packet.getCaptureHeader(), ByteBuffer.wrap(pseudopacketData));
            _metalDumper.dump(copyPacket);
        } catch (final IOException ioexc) {
            logger.severe("problem when pseudonymizing packets with the metal library");
        }
        _packetModifier.modifyPacket(packet);
        _jnetpcapDumper.dump(packet);
    }

    /**
     * Closes the three packet dump files.
     */
    @Override
    public void close() {
        _jnetpcapDumper.close();
        _referenceDumper.close();
        _metalDumper.close();

    }
}

