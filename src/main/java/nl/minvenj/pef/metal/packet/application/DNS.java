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
package nl.minvenj.pef.metal.packet.application;

import static io.parsingdata.metal.Shorthand.add;
import static io.parsingdata.metal.Shorthand.and;
import static io.parsingdata.metal.Shorthand.cho;
import static io.parsingdata.metal.Shorthand.con;
import static io.parsingdata.metal.Shorthand.def;
import static io.parsingdata.metal.Shorthand.eq;
import static io.parsingdata.metal.Shorthand.eqNum;
import static io.parsingdata.metal.Shorthand.gtNum;
import static io.parsingdata.metal.Shorthand.not;
import static io.parsingdata.metal.Shorthand.or;
import static io.parsingdata.metal.Shorthand.pre;
import static io.parsingdata.metal.Shorthand.rep;
import static io.parsingdata.metal.Shorthand.repn;
import static io.parsingdata.metal.Shorthand.self;
import static io.parsingdata.metal.Shorthand.seq;
import static io.parsingdata.metal.Shorthand.str;
import static nl.minvenj.pef.metal.CustomExpression.lastRef;

import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.metal.packet.internet.Protocol;

/**
 * DNS format definition.
 *
 * @author Netherlands Forensic Institute.
 */
public final class DNS {

    /** DNS header format definition. **/
    public static final Token HEADER = str("message header",
                                           seq(
                                               def("messageid", 2),
                                               def("qropcodeqqtcrd", 1),
                                               def("raconrcode", 1),
                                               def("qdcount", 2), // number of question entries
                                               def("ancount", 2), // number of resource records
                                               def("nscount", 2), // number of resource records in the Authority Section
                                               def("arcount", 2, // number of resource records in the Additional Section
                                                   gtNum(add(lastRef("qdcount"), add(lastRef("ancount"), add(lastRef("arcount"), self))), con(0))))); // at least 1 entry in dns data

    /** DNS label format definition. **/
    public static final Token QNAME_VALUE = seq(
                                                def("length", 1, and(not(eq(con(0x00))), // not 0 length
                                                                          eq(and(con(0xC0), self), con(0x00)))), // first bits 0 for label format
                                                def("value", lastRef("length")));

    /** DNS label terminator definition. **/
    public static final Token TERMINATOR = def("terminator", 1, eq(con(0x00)));

    private static final Token POINTER = def("pointer", 2, eq(and(con(0xC000), self), con(0xC000)));

    /** DNS qname format definition. */
    public static final Token QNAME = seq( rep(QNAME_VALUE),
                                        cho(POINTER, TERMINATOR));

    /** DNS question format definition. **/
    public static final Token QUESTION = str("dnsquestion",
                                             seq(QNAME,
                                                 def("qtype", 2),
                                                 def("qclass", 2)));

    /** DNS answer format definition. **/
    public static final Token ANSWER = str("dnsanswer",
                                           seq(QNAME,
                                               def("antype", 2),
                                               def("anclass", 2),
                                               def("anttl", 4),
                                               def("anrlength", 2),
                                               def("anrdata", lastRef("anrlength"))));

    /** DNS authority format definition. **/
    public static final Token AUTHORITY = str("dnsauthority",
                                              seq(QNAME,
                                                  def("nstype", 2),
                                                  def("nsclass", 2),
                                                  def("nsttl", 4),
                                                  def("nsrlength", 2),
                                                  def("nsrdata", lastRef("nsrlength"))));

    /** DNS additional format definition. **/
    public static final Token ADDITIONAL = str("dnsadditional",
                                               seq(QNAME,
                                                   def("adtype", 2),
                                                   def("adclass", 2),
                                                   def("adttl", 4),
                                                   def("adrlength", 2),
                                                   def("adrdata", lastRef("adrlength"))));

    /** DNS format definition. **/
    public static final Token FORMAT = str("DNS",
                                           seq(
                                               pre(def("dnslength", 2, not(eqNum(con(0)))), or(eq(lastRef("protocol"), con(Protocol.TCP)), eq(lastRef("nextheader"), con(Protocol.TCP)))), // if TCP, read 2 length bytes
                                               HEADER,
                                               repn(QUESTION, lastRef("qdcount")),
                                               repn(ANSWER, lastRef("ancount")),
                                               repn(AUTHORITY, lastRef("nscount")),
                                               repn(ADDITIONAL, lastRef("arcount"))));

    private DNS() {
    }
}