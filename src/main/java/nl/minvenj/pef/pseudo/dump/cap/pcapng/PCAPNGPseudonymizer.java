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

import java.io.File;
import java.io.IOException;

import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.encoding.Encoding;
import nl.minvenj.pef.metal.dump.PCAPNG;
import nl.minvenj.pef.metal.stream.FileByteStream;
import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.pseudo.dump.DumpFilePseudonymizer;
import nl.minvenj.pef.pseudo.dump.cap.CapUtil;
import nl.minvenj.pef.metal.GraphSerializer;
import nl.minvenj.pef.util.Util;

/**
 *  for PCAPNG files.
 *
 * Pseudonymizes packets in simple/enhanced packet blocks (types 3 and 6). Other block
 * types are written to the out file as they are.
 *
 * @author Netherlands Forensic Institute.
 */
public abstract class PCAPNGPseudonymizer implements DumpFilePseudonymizer {

    protected static final int BUFFER_SIZE = 128 * 1024;

    @Override
    public boolean supportsFile(final File file) throws IOException {
        try (final FileByteStream input = new FileByteStream(file)) {
            final ParseResult parseResult = Util.parse(input, 0, PCAPNG.SECTION_HEADER_CHO);
            return parseResult.succeeded;
        }
    }

    /**
     * Returns the encoding of the current section, which is determined by
     * the magic number contained in the Section Header Block.
     *
     * @param result the parse result of the Section Header Block
     * @return the encoding of the current section
     */
    protected Encoding getSectionEncoding(final ParseResult result) {
        final ParseGraph graph = result.environment.order;
        final byte[] magic = graph.get("magic").getValue();

        // magic number check in order to determine the section endianness
        return magic[0] == (byte) 0x1A ? PCAPNG.BIG_ENDIAN : PCAPNG.LITTLE_ENDIAN;
    }

    /**
     * Pseudonymizes parsed packet data contained in a parsed packet block. Returns the reconstructed
     * packet block with the new pseudonymized bytes.
     *
     * See {@link CapUtil#getPseudonymizedStructureBytes(FramePseudonymizer, ParseResult)}
     *
     * @param pseudonymizer the pseudonymizer to use for pseudonymization
     * @param result the packet block Metal parse result to extract packet data from
     * @return the rebuilt parsed bytes, with new pseudonymized packet data
     * @throws IOException when an I/O error occurs during parsing
     */
    protected byte[] getPseudonymizedBlockBytes(final FramePseudonymizer pseudonymizer, final ParseResult result) throws IOException {
        if (!isPacketBlock(result)) {
            GraphSerializer serializer = new GraphSerializer();
            serializer.serialize(result.environment.order);
            return serializer.data();
        }
        return CapUtil.getPseudonymizedStructureBytes(pseudonymizer, result);
    }

    private boolean isPacketBlock(final ParseResult result) {
        final int blockType = result.environment.order.get("type").asNumeric().intValue();
        return blockType == 0x00000006 || blockType == 0x00000003;
    }
}
