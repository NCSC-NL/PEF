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
import nl.minvenj.pef.metal.packet.internet.IPv4;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.process.IPv4HeaderSerializer;
import nl.minvenj.pef.serialize.transform.ParseValueTransformer;
import nl.minvenj.pef.util.ChecksumCalc;

/**
 * Used to calculate an IPv4 header checksum.
 *
 *
 * bit offset | Parameters
 * ========================================================================
 *         0  | Version | IHL |DSCP |ECN      | Total Length
 *        32  | Identification                | Flags | Fragment Offset
 *        64  | Time to Live  | Protocol      |  Header Checksum (2 bytes)
 *        96  |                       Source Address (2 bytes)
 *       128  |                       Destination Address (2 bytes)
 *       160+ |                      Options (optional max 32) + Data
 * @author Netherlands Forensic Institute.
 */
public class IPv4ChecksumCalculator implements ParseValueTransformer {

    @Override
    public Token[] context() {
        return tokens(IPv4.FORMAT);
    }

    @Override
    public ParseValue transform(final ParseValue value, final Environment environment) {
        final byte[] ipv4HeaderBytes = getIPv4Header(environment);
        // Zero the 2 checksum bytes that are inside the header. The offset of the checksum is 10 bytes.
        Arrays.fill(ipv4HeaderBytes, 10, 12, (byte) 0);
        final byte[] ipv4ChecksumBytes = ChecksumCalc.calculateInternetChecksum(ipv4HeaderBytes);
        return new ParseValue(value.name, value.getDefinition(), value.getOffset(), ipv4ChecksumBytes, value.enc);//TODO PEF-54
    }

    private byte[] getIPv4Header(final Environment environment) {
        final IPv4HeaderSerializer ipv4HeaderSerializer = new IPv4HeaderSerializer();
        new Processor().process(environment, ipv4HeaderSerializer);
        return ipv4HeaderSerializer.outputData();
    }
}