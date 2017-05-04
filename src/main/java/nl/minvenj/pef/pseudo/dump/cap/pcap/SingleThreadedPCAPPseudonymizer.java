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
package nl.minvenj.pef.pseudo.dump.cap.pcap;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.encoding.Encoding;
import nl.minvenj.pef.metal.dump.PCAP;
import nl.minvenj.pef.metal.stream.FileByteStream;
import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.pseudo.dump.cap.CapUtil;
import nl.minvenj.pef.util.Util;

/**
 * Single-threaded version of a PCAP pseudonymizer.
 *
 * @author Netherlands Forensic Institute.
 */
public final class SingleThreadedPCAPPseudonymizer extends PCAPPseudonymizer {

    private final FramePseudonymizer _framePseudonymizer;

    /**
     * Create a new PCAPPseudonymizer using a certain frame pseudonymizer.
     *
     * @param framePseudonymizer the pseudonymizer to use to transform frame data
     */
    public SingleThreadedPCAPPseudonymizer(final FramePseudonymizer framePseudonymizer) {
        _framePseudonymizer = framePseudonymizer;
    }

    @Override
    public File pseudonymize(final File inFile, final File outFile) throws IOException {
        try (final FileByteStream input = new FileByteStream(inFile);
            final OutputStream output = new BufferedOutputStream(new FileOutputStream(outFile), BUFFER_SIZE)) {
            final byte[] pcapHeader = readPCAPHeader(input);
            output.write(pcapHeader);

            final Encoding encoding = getEncoding(pcapHeader);
            long offset = pcapHeader.length;

            while (true) {
                final ParseResult result = Util.parse(input, offset, PCAP.PCAP_RECORD, encoding);
                if (!result.succeeded) {
                    break;
                }
                final byte[] recordBytes = CapUtil.getPseudonymizedStructureBytes( _framePseudonymizer, result);
                output.write(recordBytes);
                offset = result.environment.offset;
            }
        }
        return outFile;
    }
}
