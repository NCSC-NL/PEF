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

import java.io.File;
import java.io.IOException;

import io.parsingdata.metal.data.ByteStream;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.encoding.ByteOrder;
import io.parsingdata.metal.encoding.Encoding;
import nl.minvenj.pef.metal.dump.PCAP;
import nl.minvenj.pef.metal.stream.FileByteStream;
import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.pseudo.dump.DumpFilePseudonymizer;
import nl.minvenj.pef.pseudo.dump.cap.CapUtil;
import nl.minvenj.pef.util.Util;

/**
 *  for PCAP files.
 *
 * Pseudonymizes packets contained inside records.
 *
 * @author Netherlands Forensic Institute.
 */
public abstract class PCAPPseudonymizer implements DumpFilePseudonymizer {

    protected static final int BUFFER_SIZE = 128 * 1024;

    @Override
    public boolean supportsFile(final File file) throws IOException {
        try (final FileByteStream input = new FileByteStream(file)) {
            final ParseResult parseResult = Util.parse(input, 0, PCAP.GLOBAL_HEADER);
            return parseResult.succeeded;
        }
    }

    /**
     * Returns the encoding of the PCAP file, which is determined by
     * the magic number inside the PCAP header.
     *
     * @param pcapHeader the bytes of the pcap header
     * @return the encoding of the PCAP file
     */
    protected Encoding getEncoding(final byte[] pcapHeader) {
        return pcapHeader[1] == (byte) 0xB2 ? new Encoding(ByteOrder.BIG_ENDIAN) : new Encoding(ByteOrder.LITTLE_ENDIAN);
    }

    /**
     * Returns the bytes of the PCAP header.
     *
     * Requires the input byte stream to be at the beginning of the file.
     *
     * @param input the input byte stream of the PCAP file
     * @return the bytes of the PCAP header
     * @throws IOException whenever reading from the stream fails
     */
    protected byte[] readPCAPHeader(final ByteStream input) throws IOException {
        final byte[] headerBytes = new byte[24];
        input.read(0, headerBytes);
        return headerBytes;
    }

    /**
     * Pseudonymizes parsed packet data contained in a parsed record. Returns the reconstructed
     * record with the new pseudonymized bytes.
     *
     * See {@link CapUtil#getPseudonymizedStructureBytes(FramePseudonymizer, ParseResult)}
     *
     * @param pseudonymizer the pseudonymizer to use for pseudonymization
     * @param result the record Metal parse result to extract packet data from
     * @return the rebuilt parsed bytes, with new pseudonymized packet data
     * @throws IOException when an I/O error occurs during parsing
     */
    protected byte[] getPseudonymizedRecordBytes(final FramePseudonymizer pseudonymizer, final ParseResult result) throws IOException {
        return CapUtil.getPseudonymizedStructureBytes(pseudonymizer, result);
    }
}
