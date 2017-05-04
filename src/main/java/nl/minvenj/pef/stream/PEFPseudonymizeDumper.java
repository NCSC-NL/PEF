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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.logging.Logger;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.packet.PcapPacket;

import nl.minvenj.pef.pseudo.FramePseudonymizer;
/**
 * Opens a dump file and modifies the packets after which they are stored in the file.
 *
 * @author Netherlands Forensic Institute.
 */
public final class PEFPseudonymizeDumper implements PseudoPacketHandler {
    private final static Logger logger = Logger.getLogger(LiveCapture.class.getName());
    private final PcapDumper _pseudoDumper;
    private final FramePseudonymizer _pseudonymizer;

    /**
     *  Constructor for a pseudonymization packet handler using the metal library and storing the packets in a dump file.
     *
     * @param pcap the interface with the pcap (libpcap) library
     * @param destination the file to store the pack
     * @param pseudonymizer the pseudonymization settings
     */
    public PEFPseudonymizeDumper(final Pcap pcap, final String destination, final FramePseudonymizer pseudonymizer) {
        _pseudoDumper = pcap.dumpOpen(destination);
        _pseudonymizer = pseudonymizer;
    }

    /**
     * pseudonymize the packet as configured.
     *
     * @param packet the captured PcapPacket
     */
    @Override
    public void handle(PcapPacket packet) {
        //Copy the data.
        byte[] packetData = packet.getByteArray(0, packet.size());
        try {
            // If parsing fails the packet is not pseudonymized. This should logged at a lower level TODO PEF-77.
            // Packet should be discarded because pseudonymization is not guaranteed otherwise.
            final byte[] pseudopacketData  = _pseudonymizer.pseudonymize(packetData);
            PcapPacket copyPacket = new PcapPacket(packet.getCaptureHeader(), ByteBuffer.wrap(pseudopacketData));
            _pseudoDumper.dump(copyPacket);
        }
        catch (final IOException e) {
            logger.severe(e.getMessage());
        }
    }

    /**
     * Closes the dump file
     */
    @Override
    public void close() {
        _pseudoDumper.close();
    }
}
