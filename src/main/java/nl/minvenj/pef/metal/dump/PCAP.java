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
package nl.minvenj.pef.metal.dump;

import static io.parsingdata.metal.Shorthand.cho;
import static io.parsingdata.metal.Shorthand.con;
import static io.parsingdata.metal.Shorthand.def;
import static io.parsingdata.metal.Shorthand.eq;
import static io.parsingdata.metal.Shorthand.rep;
import static io.parsingdata.metal.Shorthand.seq;
import static io.parsingdata.metal.Shorthand.str;
import static nl.minvenj.pef.metal.CustomExpression.lastRef;

import io.parsingdata.metal.encoding.ByteOrder;
import io.parsingdata.metal.encoding.Encoding;
import io.parsingdata.metal.token.Token;

/**
 * PCAP format definition.
 *
 * @author Netherlands Forensic Institute.
 */
public final class PCAP {

    /** PCAP global header format definition, excluding the magic number. */
    public static final Token HEADER_WITHOUT_MAGIC_NUMBER = seq(def("versionmajor", 2),
                                                                def("versionminor", 2),
                                                                def("thiszone", 4),
                                                                def("sigfigs", 4),
                                                                def("snaplen", 4),
                                                                def("network", 4));

    /** PCAP global header format definition, excluding the magic number, interpreted as big endian. */
    public static final Token HEADER_WITHOUT_MAGIC_NUMBER_IDENTICAL = str("beheader", HEADER_WITHOUT_MAGIC_NUMBER, new Encoding(ByteOrder.BIG_ENDIAN));

    /** PCAP global header format definition, excluding the magic number, interpreted as little endian. */
    public static final Token HEADER_WITHOUT_MAGIC_NUMBER_SWAPPED = str("leheader", HEADER_WITHOUT_MAGIC_NUMBER, new Encoding(ByteOrder.LITTLE_ENDIAN));

    /** PCAP record format definition. */
    public static final Token PCAP_RECORD = str("pcaprecord",
                                                seq(
                                                    def("tssec", 4),
                                                    def("tsusec", 4),
                                                    def("incllen", 4),
                                                    def("origlen", 4),
                                                    def("packetdata", lastRef("incllen"))));

    /** PCAP record format definition, in identical byte ordering (= big endian). */
    public static final Token PCAP_RECORD_IDENTICAL = str("berecord", PCAP_RECORD, new Encoding(ByteOrder.BIG_ENDIAN));

    /** PCAP record format definition, in swapped byte ordering (= little endian). */
    public static final Token PCAP_RECORD_SWAPPED = str("lerecord", PCAP_RECORD, new Encoding(ByteOrder.LITTLE_ENDIAN));

    /** Magic number, defining identical byte ordering (= big endian). */
    public static final Token MAGIC_NUMBER_IDENTICAL = def("magicnumber", 4, eq(con(0xa1b2c3d4)));

    /** Magic number, defining swapped byte ordering (= little endian). */
    public static final Token MAGIC_NUMBER_SWAPPED = def("magicnumber", 4, eq(con(0xd4c3b2a1)));

    /** Magic number, defining identical byte ordering (= big endian) and nanosecond-resolution files. */
    public static final Token MAGIC_NUMBER_IDENTICAL_NANO = def("magicnumber", 4, eq(con(0xa1b23c4d)));

    /** Magic number, defining swapped byte ordering (= little endian) and nanosecond-resolution files. */
    public static final Token MAGIC_NUMBER_SWAPPED_NANO = def("magicnumber", 4, eq(con(0x4d3cb2a1)));

    /** PCAP global header format definition, in identical byte ordering (= big endian). */
    public static final Token GLOBAL_HEADER_IDENTICAL = seq(cho(MAGIC_NUMBER_IDENTICAL, MAGIC_NUMBER_IDENTICAL_NANO), HEADER_WITHOUT_MAGIC_NUMBER_IDENTICAL);

    /** PCAP global header format definition, in swapped byte ordering (= little endian). */
    public static final Token GLOBAL_HEADER_SWAPPED = seq(cho(MAGIC_NUMBER_SWAPPED, MAGIC_NUMBER_SWAPPED_NANO), HEADER_WITHOUT_MAGIC_NUMBER_SWAPPED);

    /** PCAP global header format definition. */
    public static final Token GLOBAL_HEADER = str("pcapheader",
                                                  cho(
                                                      GLOBAL_HEADER_IDENTICAL,
                                                      GLOBAL_HEADER_SWAPPED));

    /** PCAP file format definition. */
    public static final Token FORMAT = cho(
                                           seq(GLOBAL_HEADER_IDENTICAL, rep(PCAP_RECORD_IDENTICAL)),
                                           seq(GLOBAL_HEADER_SWAPPED, rep(PCAP_RECORD_SWAPPED)));

    private PCAP() {
    }
}
