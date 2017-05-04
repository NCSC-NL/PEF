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
package nl.minvenj.pef.serialize.transform.checksum;

import static nl.minvenj.pef.util.Util.tokens;
import static nl.minvenj.pef.util.Util.unsignedShortToByteArray;

import java.nio.ByteOrder;
import java.util.Arrays;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.metal.packet.internet.IPv4;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.process.TCPHeaderPayloadSerializer;
import nl.minvenj.pef.serialize.transform.ParseValueTransformer;
import nl.minvenj.pef.util.ChecksumCalc;
import nl.minvenj.pef.util.Util;

/**
 * Used to calculate an IPv4 TCP checksum.
 *
 * The checksum is calculated over a pseudo header, IPv4 header and data.
 *
 * bit offset | Parameters
 * ========================================================================
 *         0  |                Source IPv4 address (4 bytes)
 *        32  |              Destination IPv4 address (4 bytes)
 *        64  |   Zeroes  |   Protocol  |  TCP Length (2 bytes)
 *        ----------------------------------------------------------------------------
 *        96  |  Source Port (2 bytes)  | Destination Port (2 bytes)
 *       128  |                   Sequence number
 *       160  |               Acknowledgement number
 *       192  | Off. + Res | Flags      | Window (2 bytes)
 *       224  | Checksum (2 bytes)      | Urgent pointer (2 bytes)
 *       256+ | Options (optional) + Data
 * @author Netherlands Forensic Institute.
 */
public class IPv4TCPChecksumCalculator implements ParseValueTransformer {

    @Override
    public Token[] context() {
        return tokens(IPv4.FORMAT);
    }

    @Override
    public ParseValue transform(final ParseValue value, final Environment environment) {
        final byte[] tcpChecksumBytes = calculateChecksum(environment);
        return new ParseValue(value.name, value.getDefinition(), value.getOffset(), tcpChecksumBytes, value.enc);
    }

    private byte[] calculateChecksum(final Environment environment) {
        final ParseGraph values = environment.order;

        // The checksum is calculated over the pseudo header, and the tcp segment (tcp header and tcp data)
        // The tcp length which is part of the pseudo header needs to be calculated separately. The TCP header and data length
        // is equal to the total ip length minus the ipv4 internet header length.
        final byte[] srcIP = values.get("ipsource").getValue();
        final byte[] dstIP = values.get("ipdestination").getValue();
        final byte[] zeroes = new byte[1];
        final byte[] protocol = values.get("protocol").getValue();
        final byte[] tcplength = unsignedShortToByteArray(values.get("iplength").asNumeric().intValue()
                - ((values.get("versionihl").asNumeric().intValue() & 0xF) * 4), ByteOrder.BIG_ENDIAN);
        final byte[] tcpData = getTCPPayload(environment);

        final byte[] mergedBytes = Util.concatBytes(srcIP, dstIP, zeroes, protocol, tcplength, tcpData);
        // Zero the 2 checksum bytes that are inside the header. The offset is 28.
        Arrays.fill(mergedBytes, 28, 30, (byte) 0);
        return ChecksumCalc.calculateInternetChecksum(mergedBytes);
    }

    private byte[] getTCPPayload(final Environment environment) {
        final TCPHeaderPayloadSerializer tcpPayloadSerializer = new TCPHeaderPayloadSerializer();
        new Processor().process(environment, tcpPayloadSerializer);
        return tcpPayloadSerializer.outputData();
    }
}