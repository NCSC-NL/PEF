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

import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;

import nl.minvenj.pef.pseudo.IPPseudonymizer;
/**
 * Packethandler that opens a dump file and stores pseudonymized packets into the file.
 *
 * @author Netherlands Forensic Institute.
 */
public class JNetPcapPseudonymizeDumper implements PseudoPacketHandler {

    private static final Logger logger = Logger.getLogger(LiveCapture.class.getName());
    private final PcapDumper _pseudoDumper;
    private final JNetPcapPacketModifier _packetModifier;

    /**
     * Constructor initializing the settings for pseudonymization.
     *
     * @param pcap the interface with the pcap library
     * @param destination the file to store the captured packets
     * @param pseudonymizerMap mapping of ip type and pseudonymizer to be used
     * @param checksumList the list of protocols for which the checksum must be recalculated
     */
    JNetPcapPseudonymizeDumper(final Pcap pcap, final String destination, final Map<JProtocol, IPPseudonymizer> pseudonymizerMap, final List<Integer> checksumList) {
        _pseudoDumper = pcap.dumpOpen(destination);
        _packetModifier = new JNetPcapPacketModifier(pseudonymizerMap, checksumList, true);
    }

    /**
     * pseudonymizes the packet according to the settings and stored the
     *
     * @param packet the captured PcapPacket
     */
    @Override
    public void handle(PcapPacket packet) {
        // Determine if the packet is an ethernet packet first.
        if (packet.hasHeader(Ethernet.ID)){
            _packetModifier.modifyPacket(packet);
            _pseudoDumper.dump(packet);
        }
        else {
            // TODO PEF-77: don't send or nullify the packet.
            logger.warning("Non-ethernet packet found, packet is left untouched.");
        }
    }

    /**
     * closes the dump file
     */
    @Override
    public void close() {
        _pseudoDumper.close();
    }
}
