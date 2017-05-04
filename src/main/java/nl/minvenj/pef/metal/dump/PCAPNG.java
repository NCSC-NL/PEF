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
import static io.parsingdata.metal.Shorthand.eqNum;
import static io.parsingdata.metal.Shorthand.not;
import static io.parsingdata.metal.Shorthand.rep;
import static io.parsingdata.metal.Shorthand.seq;
import static io.parsingdata.metal.Shorthand.sub;
import static nl.minvenj.pef.metal.CustomExpression.enc;
import static nl.minvenj.pef.metal.CustomExpression.lastRef;

import io.parsingdata.metal.encoding.ByteOrder;
import io.parsingdata.metal.encoding.Encoding;
import io.parsingdata.metal.token.Token;

/**
 * PCAPNG format definition.
 *
 * @author Netherlands Forensic Institute.
 */
public final class PCAPNG {

    /** Little endian encoding. */
    public static final Encoding LITTLE_ENDIAN = new Encoding(ByteOrder.LITTLE_ENDIAN);

    /** Big endian encoding. */
    public static final Encoding BIG_ENDIAN = new Encoding(ByteOrder.BIG_ENDIAN);

    /** Defines the most important characteristics of the interface(s) used for capturing traffic. */
    // required before simple/enhanced packet blocks
    public static final Token INTERFACE_DESCRIPTION = seq(
                                                          def("type", 4, eqNum(con(0x00000001))),
                                                          def("length", 4),
                                                          def("linktype", 2),
                                                          def("reserved", 2),
                                                          def("snaplen", 4),
                                                          def("options", sub(lastRef("length"), con(20))),
                                                          def("length", 4));

    /** Contains a single captured packet, or a portion of it, with only a minimal set of information about it. */
    public static final Token SIMPLE_PACKET = seq(
                                                  def("type", 4, eqNum(con(0x00000003))),
                                                  def("length", 4),
                                                  def("originallength", 4),
                                                  def("packetdata", sub(lastRef("length"), con(16))),
                                                  def("length", 4));

    /** Contains a single captured packet, or a portion of it. */
    public static final Token ENHANCED_PACKET = seq(
                                                    def("type", 4, eqNum(con(0x00000006))),
                                                    def("length", 4),
                                                    def("interfaceid", 4),
                                                    def("timestamphigh", 4),
                                                    def("timestamplow", 4),
                                                    def("capturedlength", 4),
                                                    def("originallength", 4),
                                                    def("packetdata", lastRef("capturedlength")),
                                                    def("options", sub(sub(lastRef("length"), con(32)), lastRef("capturedlength"))),
                                                    def("length", 4));

    /** General block description for yet unknown or unimplemented block types. */
    public static final Token OTHER_BLOCK = seq(
                                                def("type", 4, not(eq(con(0x0A0D0D0A)))),
                                                def("length", 4),
                                                def("body", sub(lastRef("length"), con(12))),
                                                def("length", 4));

    /** A PCAPNG block description. */
    public static final Token BLOCK = cho(
                                          ENHANCED_PACKET,
                                          SIMPLE_PACKET,
                                          OTHER_BLOCK,
                                          INTERFACE_DESCRIPTION);

    /** Defines the most important characteristics of the capture file (BE). */
    public static final Token SECTION_HEADER = seq(
                                                   def("type", 4, eq(con(0x0A0D0D0A))),
                                                   def("length", 4),
                                                   def("magic", 4, eqNum(con(0x1A2B3C4D))),
                                                   def("majorversion", 2),
                                                   def("minorversion", 2),
                                                   def("sectionlength", 8),
                                                   def("options", sub(lastRef("length"), con(28))), // 28 because this would be the size without options
                                                   def("length", 4));

    /** Identifies the beginning of a section in a PCAPNG file (identifies a list of blocks (interfaces, packets) that are logically correlated). */
    public static final Token SECTION = cho(
                                            seq(LITTLE_ENDIAN,
                                                SECTION_HEADER,
                                                rep(BLOCK)),
                                            seq(BIG_ENDIAN,
                                                SECTION_HEADER,
                                                rep(BLOCK)));

    /** Section header, big endian or little endian. */
    public static final Token SECTION_HEADER_CHO = cho(
                                                       enc(SECTION_HEADER,
                                                           BIG_ENDIAN),
                                                       enc(
                                                           SECTION_HEADER,
                                                           LITTLE_ENDIAN));

    /** The PCAPNG format definition. */
    public static final Token FORMAT = rep(SECTION);

    private PCAPNG() {
    }
}
