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
package nl.minvenj.pef.metal.packet.transport;

import static io.parsingdata.metal.Shorthand.add;
import static io.parsingdata.metal.Shorthand.cho;
import static io.parsingdata.metal.Shorthand.con;
import static io.parsingdata.metal.Shorthand.def;
import static io.parsingdata.metal.Shorthand.eqNum;
import static io.parsingdata.metal.Shorthand.gtNum;
import static io.parsingdata.metal.Shorthand.mul;
import static io.parsingdata.metal.Shorthand.offset;
import static io.parsingdata.metal.Shorthand.pre;
import static io.parsingdata.metal.Shorthand.seq;
import static io.parsingdata.metal.Shorthand.shr;
import static io.parsingdata.metal.Shorthand.str;
import static io.parsingdata.metal.Shorthand.sub;
import static nl.minvenj.pef.metal.CustomExpression.lastRef;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.encoding.Encoding;
import io.parsingdata.metal.expression.comparison.ComparisonExpression;
import io.parsingdata.metal.expression.value.BinaryValueExpression;
import io.parsingdata.metal.data.OptionalValueList;
import io.parsingdata.metal.expression.value.ValueExpression;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.metal.packet.application.DNS;
import nl.minvenj.pef.metal.packet.internet.IPv4;
import nl.minvenj.pef.metal.packet.internet.IPv6;

/**
 * TCP format definition.
 *
 * @author Netherlands Forensic Institute.
 */
public final class TCP {

    /** Header size in octets. */
    public static final BinaryValueExpression HEADER_SIZE = mul(shr(lastRef("doresfl"), con(12)), con(4));

    /** Offset of the TCP segment. */
    public static final ValueExpression OFFSET = offset(lastRef("sourceport"));

    /** Data size in octets. */
    public static final ValueExpression DATA_SIZE = new ValueExpression() {
        // this new class is needed because of the circular references from TCP to TCP, which breaks with static initialization
        @Override
        public OptionalValueList eval(final Environment env, final Encoding enc) {
            final ComparisonExpression isIPv4 = eqNum(shr(lastRef("versionihl"), con(4)), con(4));
            if (isIPv4.eval(env, enc)) {
                return sub(IPv4.TOTAL_SIZE, add(IPv4.HEADER_SIZE, TCP.HEADER_SIZE)).eval(env, enc);
            }

            final ComparisonExpression isIPv6 = eqNum(shr(lastRef("vertraflo"), con(28)), con(6));
            if (isIPv6.eval(env, enc)) {
                final ValueExpression ipv6PayloadLeft = sub(IPv6.PAYLOAD_SIZE, sub(TCP.OFFSET, IPv6.PAYLOAD_OFFSET));
                return sub(ipv6PayloadLeft, TCP.HEADER_SIZE).eval(env, enc);
            }

            throw new RuntimeException("not IPv4 or IPv6");
        }
    };

    /** TCP header format definition. **/
    public static final Token HEADER = str("tcpheader",
                                           seq(
                                               def("sourceport", 2),
                                               def("destinationport", 2),
                                               def("seqnumber", 4),
                                               def("acknumber", 4),
                                               def("doresfl", 2), // data offset, reserved, flags
                                               def("windowsize", 2),
                                               def("tcpchecksum", 2),
                                               def("urgentpointer", 2),
                                               pre(
                                                   def("options", sub(TCP.HEADER_SIZE, con(20))), // size = TCP header size - 20 bytes
                                                   gtNum(TCP.HEADER_SIZE, con(20))))); // header size > 5 * 4 bytes for options (data offset > 5)

    /** TCP data format definition. **/
    public static final Token DATA = cho(
                                         DNS.FORMAT,
                                         def("tcpdata", DATA_SIZE)); // needed for checksum calculations, otherwise not all bytes are present if not DNS

    /** TCP format definition. **/
    public static final Token FORMAT = str("TCP", seq(HEADER, DATA));

    private TCP() {
    }
}
