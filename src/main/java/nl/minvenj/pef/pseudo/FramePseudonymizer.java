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
package nl.minvenj.pef.pseudo;

import java.io.IOException;

import io.parsingdata.metal.data.ParseResult;
import nl.minvenj.pef.metal.packet.link.Ethernet2Frame;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.process.CopyTokenSerializer;
import nl.minvenj.pef.util.Util;

/**
 *  for ethernet frames.
 *
 * @author Netherlands Forensic Institute.
 */
public final class FramePseudonymizer {
    private final Processor _pseudonymizer;

    public FramePseudonymizer(final Processor pseudonymizer) {
        _pseudonymizer = pseudonymizer;
    }

    /**
     * Pseudonymizes an ethernet frame, based on the serializer settings.
     *
     * When parsing the bytes fails, the input array is returned without changes.
     *
     * @param frameBytes the bytes of the frame
     * @return the bytes of the frame pseudonymized based on the serializer settings, or frameBytes if parsing failed
     * @throws IOException whenever I/O errors occur
     */
    public byte[] pseudonymize(final byte[] frameBytes) throws IOException {
        final ParseResult result = Util.parse(frameBytes, Ethernet2Frame.FORMAT);
        if (result.succeeded && result.environment.offset == frameBytes.length) {
            final CopyTokenSerializer copySerializer = new CopyTokenSerializer(frameBytes.length);
            _pseudonymizer.transformAndProcess(result, copySerializer);
            return copySerializer.outputData();
        }
        // TODO PEF-61 add logging
        return frameBytes;
    }
}
