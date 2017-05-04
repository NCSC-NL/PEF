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

import java.util.Arrays;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.metal.packet.internet.ICMP;
import nl.minvenj.pef.metal.packet.internet.IPv4;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.process.ICMPHeaderPayloadSerializer;
import nl.minvenj.pef.serialize.transform.ParseValueTransformer;
import nl.minvenj.pef.util.ChecksumCalc;

/**
 * Used to calculate an IPv4 ICMP checksum.
 *
 * bit offset | Parameters
 * ==================================================================
 *         0  | Type |  Code  | Checksum (2 bytes)
 *        32  |          Rest of header
 *
 * @author Netherlands Forensic Institute.
 */
public class IPv4ICMPChecksumCalculator implements ParseValueTransformer {

    @Override
    public Token[] context() {
        return tokens(IPv4.FORMAT, ICMP.FORMAT);
    }

    @Override
    public ParseValue transform(final ParseValue value, final Environment environment) {
        final byte[] icmpPacket = getICMPHeaderPayload(environment);
        // Zero the 2 checksum bytes that are inside the header. The offset is 2.
        Arrays.fill(icmpPacket, 2, 4,(byte) 0);
        final byte[] icmpChecksumBytes = ChecksumCalc.calculateInternetChecksum(icmpPacket);
        return new ParseValue(value.name, value.getDefinition(), value.getOffset(), icmpChecksumBytes, value.enc);
    }

    private byte[] getICMPHeaderPayload(final Environment environment) {
        final ICMPHeaderPayloadSerializer icmpHeaderPayloadSerializer = new ICMPHeaderPayloadSerializer();
        new Processor().process(environment, icmpHeaderPayloadSerializer);
        return icmpHeaderPayloadSerializer.outputData();
    }
}
