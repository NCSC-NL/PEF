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
package nl.minvenj.pef.pseudo.dump.cap.pcapng;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.encoding.Encoding;
import nl.minvenj.pef.metal.dump.PCAPNG;
import nl.minvenj.pef.metal.stream.InputStreamByteStream;
import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.util.Util;

/**
 * Single-threaded version of a PCAPNG pseudonymizer.
 *
 * @author Netherlands Forensic Institute.
 */
public class SingleThreadedPCAPNGPseudonymizer extends PCAPNGPseudonymizer {

    private final FramePseudonymizer _framePseudonimyzer;

    /**
     * Create a new PCAPNGPseudonymizer using a certain frame pseudonymizer.
     *
     * @param framePseudonymizer the pseudonymizer to use to transform frame data
     */
    public SingleThreadedPCAPNGPseudonymizer(final FramePseudonymizer framePseudonymizer) {
        _framePseudonimyzer = framePseudonymizer;
    }

    @Override
    public File pseudonymize(final File inFile, final File outFile) throws IOException {

        try (final InputStreamByteStream input = new InputStreamByteStream(new FileInputStream(inFile));
             final OutputStream output = new BufferedOutputStream(new FileOutputStream(outFile), BUFFER_SIZE)) {

            long offset = 0;
            Encoding encoding = null;

            while (true) {
                ParseResult result = Util.parse(input, offset, PCAPNG.SECTION_HEADER_CHO);

                // if result succeeded, we found a section header block
                if (result.succeeded) {
                    // new encoding from now on (current section)
                    encoding = getSectionEncoding(result);
                }
                else {
                    result = Util.parse(input, offset, PCAPNG.BLOCK, encoding);
                }

                if (!result.succeeded) {
                    break;
                }

                final byte[] blockBytes = getPseudonymizedBlockBytes(_framePseudonimyzer, result);
                output.write(blockBytes);

                offset = result.environment.offset;
            }
        }

        return outFile;
    }
}
