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

import static nl.minvenj.pef.util.ChecksumCalc.calculateInternetChecksum;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Map;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import nl.minvenj.pef.pseudo.IPPseudonymizer;
import nl.minvenj.pef.util.Util;
/**
 * JNetPcapPacketModifier is used to modify pcap packets. Ipv4 and Ipv6 packets can be
 * pseudonymized and optional checksums are recalculated.
 *
 * @author Netherlands Forensic Institute.
 */
public class JNetPcapPacketModifier {
    private final Map<JProtocol, IPPseudonymizer> _pseudonymizerMap;
    private final List<Integer> _checksumList;
    private final boolean DNS_ONLY;

    /**
     * JNetPcapPacketModifier  constructor that initializes the pseudonymization settings.
     *
     * @param pseudonymizerMap the map with the pseudonymizer settings
     * @param checksumList the list of checksums to be recalculated
     * @param dnsOnly boolean if only DNS packets need to be pseudonymized.
     */
    JNetPcapPacketModifier(final Map<JProtocol, IPPseudonymizer> pseudonymizerMap, final List<Integer> checksumList, final boolean dnsOnly) {
        _pseudonymizerMap = pseudonymizerMap;
        _checksumList = checksumList;
       DNS_ONLY = dnsOnly;
    }

    /**
     * In this function the packet is pseudonymization and checksums are recalculated as configured.
     *
     * @param packet the captured packet
     */
    public void modifyPacket(JPacket packet) {
        if ((!DNS_ONLY) || isDns(packet)) {
            // If the original ip4 checksum is not valid, the checksum should not be modified.
            boolean originalChecksumValid = true;

            if (_pseudonymizerMap.containsKey(JProtocol.IP4) && packet.hasHeader(Ip4.ID)) {
                Ip4 ip4 = packet.getHeader(new Ip4());
                originalChecksumValid = ip4.isChecksumValid();
                pseudonymizeIP4(_pseudonymizerMap.get(JProtocol.IP4), ip4);
            } else if (_pseudonymizerMap.containsKey(JProtocol.IP6) && packet.hasHeader(Ip6.ID)) {
                Ip6 ip6 = packet.getHeader(new Ip6());
                pseudonymizeIP6(_pseudonymizerMap.get(JProtocol.IP6), ip6);
            }
            // Checksum updates.
            recalculateChecksums(packet, originalChecksumValid);
        }
    }

    /**
     * Recalculates the checksums as configured.
     *
     * @param packet the captured packet
     * @param originalChecksumValid boolean that holds whether the checksum was valid before modification.
     */
    private void recalculateChecksums(final JPacket packet, final boolean originalChecksumValid) {
        for (int checksumType : _checksumList) {
            // The ip4 or ip6 checksum should be updated first.
            if (checksumType == Ip4.ID && originalChecksumValid) {
                if (packet.hasHeader(Ip4.ID)) {
                    Ip4 ip4 = packet.getHeader(new Ip4());
                    ip4.recalculateChecksum();
                }
            }
            if (checksumType == Udp.ID && packet.hasHeader(Udp.ID)) {
                recalulateUdpChecksum(packet);
            }
            if (checksumType == Tcp.ID && packet.hasHeader(Tcp.ID)) {
                Tcp tcp = packet.getHeader(new Tcp());
                tcp.recalculateChecksum();
            }
            if (checksumType == Icmp.ID && packet.hasHeader(Icmp.ID)) {
                Icmp icmp = packet.getHeader(new Icmp());
                icmp.recalculateChecksum();
            }
        }
    }

    /**
     * Within JNetPcap the UDP checksum recalculation does not work.
     * It is reimplemented here.
     *
     * @param packet packet to recalculate the udp checksum over.
     */
    private void recalulateUdpChecksum(final JPacket packet) {
        final Udp udp = packet.getHeader(new Udp());
        udp.checksum(0); // The checksum is left out of the calculation but reset for correctness.
        final byte[] mergedBytes;
        if (packet.hasHeader(Ip4.ID)) {
            Ip4 ip4 = packet.getHeader(new Ip4());
            mergedBytes = constructIp4UdpChecksumByteArray(ip4, udp);
        } else {
            Ip6 ip6 = packet.getHeader(new Ip6());
            mergedBytes = constructIp6UdpChecksumByteArray(ip6, udp);
        }
        udp.checksum(ByteBuffer.wrap(calculateInternetChecksum(mergedBytes)).order(ByteOrder.BIG_ENDIAN).getShort());
    }

    /**
     * Constructs the byte array over which the Ipv4 UDP checksum is calculated.
     * Ip4 Pseudo header + data
     *
     * @param ip4 the ip4 header
     * @param udp the udp header
     * @return byte array
     */
    private byte[] constructIp4UdpChecksumByteArray(final Ip4 ip4, final Udp udp) {
        return (Util.concatBytes(ip4.source(), ip4.destination(), new byte[1], new byte[]{(byte)0x11},
                Util.unsignedShortToByteArray(udp.length(), ByteOrder.BIG_ENDIAN),
                Util.unsignedShortToByteArray(udp.source(), ByteOrder.BIG_ENDIAN),
                Util.unsignedShortToByteArray(udp.destination(), ByteOrder.BIG_ENDIAN),
                Util.unsignedShortToByteArray(udp.length(), ByteOrder.BIG_ENDIAN),
                udp.getPayload()));
    }

    /**
     * Constructs the byte array over which the Ipv4 UDP checksum is calculated.
     * Ip6 Pseudo header + data
     *
     * @param ip6 the Ipv6 header
     * @param udp the udp header
     * @return byte array
     */
    private byte[] constructIp6UdpChecksumByteArray(final Ip6 ip6, final Udp udp) {
        return (Util.concatBytes(ip6.source(), ip6.destination(),
                Util.unsignedShortToByteArray(udp.length(), ByteOrder.BIG_ENDIAN),
                new byte[3], new byte[]{(byte) 0x11},
                Util.unsignedShortToByteArray(udp.source(), ByteOrder.BIG_ENDIAN),
                Util.unsignedShortToByteArray(udp.destination(), ByteOrder.BIG_ENDIAN),
                Util.unsignedShortToByteArray(udp.length(), ByteOrder.BIG_ENDIAN),
                udp.getPayload()));
    }

    /**
     * Pseudonymizes the Ipv4 source and destination.
     *
     * @param pseudonymizer pseudonymizer containing the algorithm used for pseudonymization.
     * @param ip4 the Ipv4 header
     */
    private void pseudonymizeIP4(final IPPseudonymizer pseudonymizer, final Ip4 ip4) {
        ip4.source(pseudonymizer.pseudonymize(ip4.source()));
        ip4.destination(pseudonymizer.pseudonymize(ip4.destination()));
    }

    /**
     * Pseudonymizes the Ipv6 source and destination.
     *
     * @param pseudonymizer pseudonymizer containing the algorithm used for pseudonymization.
     * @param ip6 the Ipv6 header.
     */
    private void pseudonymizeIP6(final IPPseudonymizer pseudonymizer, final Ip6 ip6) {
        // Transfer the bytes from a bytebuffer to the correct offset inside the header.
        ip6.transferFrom(ByteBuffer.wrap(pseudonymizer.pseudonymize(ip6.source())), 8);
        ip6.transferFrom(ByteBuffer.wrap(pseudonymizer.pseudonymize(ip6.destination())), 24);
    }

    /**
     * Check for DNS packets if required that only DNS packets should be handled.
     *
     * @param packet the captured packet.
     * @return true if the packet is a dns packet.
     */
    private boolean isDns(final JPacket packet) {
        if (packet.hasHeader(Udp.ID)) {
            final Udp udp = packet.getHeader(new Udp());
            return (udp.source() == 53 || udp.destination() == 53);
        }
        else if (packet.hasHeader(Tcp.ID)) {
            final Tcp tcp = packet.getHeader(new Tcp());
            return (tcp.source() == 53 || tcp.destination() == 53);
        }
        return false;
    }
}
