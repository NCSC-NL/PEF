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

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.metal.packet.internet.IPv4;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.process.UDPPayloadSerializer;
import nl.minvenj.pef.serialize.transform.ParseValueTransformer;
import nl.minvenj.pef.util.ChecksumCalc;
import nl.minvenj.pef.util.Util;

/**
 * Used to calculate an IPv4 UDP checksum.
 *
 * The checksum is calculated over a pseudo header, IPv4 header and data.
 *
 * bit offset | Parameters
 * =================================================================================
 *         0  |                          Source IPv4 address (4 bytes)
 *        32  |                          Destination IPv6 address (4 bytes)
 *        64  | Zeroes (1 byte)| Protocol (1 byte) | UDP Length (2 bytes)
 *        96  |        Source Port (2 bytes)       | Destination Port (2 byte)
 *       128  |        Length (2 bytes)            | Checksum (2 bytes)
 *       160+ |                                   Data
 *
 * @author Netherlands Forensic Institute.
 */
public class IPv4UDPChecksumCalculator implements ParseValueTransformer {

    @Override
    public Token[] context() {
        return tokens(IPv4.FORMAT);
    }

    @Override
    public ParseValue transform(final ParseValue value, final Environment environment) {
        final byte[] udpChecksumBytes = calculateChecksum(environment);
        return new ParseValue(value.name, value.getDefinition(), value.getOffset(), udpChecksumBytes, value.enc);
    }

    private byte[] calculateChecksum(final Environment environment) {
        final ParseGraph values = environment.order;

        final byte[] sourceIP = values.get("ipsource").getValue();
        final byte[] destinationIP = values.get("ipdestination").getValue();
        final byte[] zeroes = new byte[1];
        final byte[] protocol = values.get("protocol").getValue();
        final byte[] udpLength= values.get("udplength").getValue();
        final byte[] sourcePort = values.get("sourceport").getValue();
        final byte[] destinationPort = values.get("destinationport").getValue();
        final byte[] udpPayload = getUDPPayload(environment);
        final byte[] checksum = new byte[2];
        final byte[] mergedBytes = Util.concatBytes(sourceIP, destinationIP, zeroes, protocol, udpLength , sourcePort, destinationPort, udpLength, checksum, udpPayload);
        return ChecksumCalc.calculateInternetChecksum(mergedBytes);
    }

    public byte[] getUDPPayload(final Environment environment) {
        final UDPPayloadSerializer udpPayloadSerializer = new UDPPayloadSerializer();
        new Processor().process(environment, udpPayloadSerializer);
        return udpPayloadSerializer.outputData();
    }
}