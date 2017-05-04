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

import java.nio.ByteBuffer;
import java.util.Arrays;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.metal.packet.internet.IPv6;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.process.TCPHeaderPayloadSerializer;
import nl.minvenj.pef.serialize.transform.ParseValueTransformer;
import nl.minvenj.pef.util.ChecksumCalc;
import nl.minvenj.pef.util.Util;

/**
 * Used to calculate an IPv6 TCP checksum.
 *
 * The checksum is calculated over a pseudo header, IPv6 header and data.
 *
 * bit offset | Parameters
 * ========================================================================
 *         0  | Source IPv6 address (16 bytes)
 *       128  | Destination IPv6 address (16 bytes)
 *       256  | TCP Length (4 bytes)
 *       288  | Zeroes (3 bytes)        | Next Header (1 byte)
 *--------------------------------------------------------------------------
 *       320  | Source Port (2 bytes)   | Destination Port (2 bytes)
 *       352  |                 Sequence number
 *       384  |               Acknowledgement number
 *       416  | Off. + Res | Flags      | Window (2 bytes)
 *       448  | Checksum (2 bytes)      | Urgent pointer (2 bytes)
 *       480+ | Options (optional max 32) + Data
 *
 * @author Netherlands Forensic Institute.
 */
public class IPv6TCPChecksumCalculator implements ParseValueTransformer {

    @Override
    public Token[] context() {
        return tokens(IPv6.FORMAT);
    }

    @Override
    public ParseValue transform(final ParseValue value, final Environment environment) {
        final byte[] tcpChecksumBytes = calculateChecksum(environment);
        return new ParseValue(value.name, value.getDefinition(), value.getOffset(), tcpChecksumBytes, value.enc);
    }

    private byte[] calculateChecksum(final Environment environment) {
        final ParseGraph values = environment.order;

        final byte[] tcpPayload = getTCPPayload(environment);

        final byte[] srcIP = values.get("sourceaddress").getValue();
        final byte[] dstIP = values.get("destinationaddress").getValue();
        final byte[] tcplength = ByteBuffer.allocate(4).putInt(tcpPayload.length).array();
        final byte[] zeroes = new byte[3];
        final byte[] nextheader = values.get("nextheader").getValue();
        final byte[] mergedBytes = Util.concatBytes(srcIP, dstIP, tcplength, zeroes, nextheader, tcpPayload);

        // Calculate the offset of the checksum and zero the bytes.
        final int checksumOffset = 56;
        Arrays.fill(mergedBytes, checksumOffset, checksumOffset + 2, (byte) 0);
        return ChecksumCalc.calculateInternetChecksum(mergedBytes);
    }

    private byte[] getTCPPayload(final Environment environment) {
        final TCPHeaderPayloadSerializer tcpPayloadSerializer = new TCPHeaderPayloadSerializer();
        new Processor().process(environment, tcpPayloadSerializer);
        return tcpPayloadSerializer.outputData();
    }
}