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
package nl.minvenj.pef.util;

import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseResult;
import nl.minvenj.pef.metal.dump.PCAP;
import nl.minvenj.pef.metal.dump.PCAPNG;
import nl.minvenj.pef.metal.packet.link.Ethernet2Frame;
import nl.minvenj.pef.metal.stream.FileByteStream;
import nl.minvenj.pef.pseudo.cli.CLTool;
import org.apache.commons.lang3.tuple.Pair;

import java.io.File;
import java.io.IOException;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class CLToolTestUtil {

    public static final String PEF_COMMAND = "-4 30313233343536373839414243444546 /16 -6 30313233343536373839414243444546 /64 -c all";

    /** Return a pair of ParseGraphs containing the parsed values from each file respectively, after running given command. */
    public static Pair<ParseGraph, ParseGraph> getValues(final File preFile, final File postFile, final String command) throws IOException {
        runWithCommand(preFile, postFile, command);

        final Pair<ParseGraph, ParseGraph> pair = getValues(preFile, postFile);
        assertThat(pair.getLeft().size, is(equalTo(pair.getRight().size)));

        return pair;
    }

    /** Return a pair of ParseGraphs containing the parsed values from each file respectively. */
    private static Pair<ParseGraph, ParseGraph> getValues(final File preFile, final File postFile) throws IOException {
        final ParseGraph valuesFromPreDumpFile = getValuesFromDumpFile(preFile);
        final ParseGraph valuesFromPostDumpFile = getValuesFromDumpFile(postFile);

        return Pair.of(valuesFromPreDumpFile, valuesFromPostDumpFile);
    }

    /** Return a pair of ParseGraphs containing the parsed values from the packet contained in each file respectively, after running given command. */
    public static Pair<ParseGraph, ParseGraph> getPacketValues(final File preFile, final File postFile, final String command) throws IOException {
        runWithCommand(preFile, postFile, command);

        final Pair<ParseGraph, ParseGraph> pair = getPacketValues(preFile, postFile);
        assertThat(pair.getLeft().size, is(equalTo(pair.getRight().size)));

        return pair;
    }

    /** Return a pair of ParseGraphs containing the parsed values from the packet contained in each file respectively. */
    private static Pair<ParseGraph, ParseGraph> getPacketValues(final File preFile, final File postFile) throws IOException {
        final ParseGraph packetValuesFromPreDumpFile = getPacketValuesFromDumpFile(preFile);
        final ParseGraph packetValuesFromPostDumpFile = getPacketValuesFromDumpFile(postFile);

        return Pair.of(packetValuesFromPreDumpFile, packetValuesFromPostDumpFile);
    }

    /** Return a ParseGraph containing the parsed values from the given file. */
    public static ParseGraph getValuesFromDumpFile(final File dumpFile) throws IOException {
        final FileByteStream input = new FileByteStream(dumpFile);
        ParseResult parse = Util.parse(input, PCAP.FORMAT);
        if (!parse.succeeded) {
            parse = Util.parse(input, PCAPNG.FORMAT);
        }

        assertTrue(parse.succeeded);
        assertThat(parse.environment.offset, is(equalTo(input.getSize())));

        return parse.environment.order.reverse();
    }

    /** Return a ParseGraph containing the parsed values from the packet contained in the given file. */
    public static ParseGraph getPacketValuesFromDumpFile(final File dumpFile) throws IOException {
        ParseResult result = Util.parse(new FileByteStream(dumpFile), PCAP.FORMAT);
        if (!result.succeeded) {
            result = Util.parse(new FileByteStream(dumpFile), PCAPNG.FORMAT);
            assertTrue(result.succeeded);
        }
        final byte[] packetBytes = result.environment.order.get("packetdata").getValue();

        final ParseResult parse = Util.parse(packetBytes, Ethernet2Frame.FORMAT);

        assertTrue(parse.succeeded);
        assertThat(parse.environment.offset, is(equalTo((long) packetBytes.length)));

        return parse.environment.order.reverse();
    }

    public static void runPEF(final File preFile, final File postFile) {
        runWithCommand(preFile, postFile, PEF_COMMAND);
    }

    public static void runWithCommand(final File preFile, final File postFile, final String command) {
        final String[] cmd = String.format("-i %s -o %s %s", preFile, postFile, command).split(" ");
        CLTool.main(cmd);
    }
}
