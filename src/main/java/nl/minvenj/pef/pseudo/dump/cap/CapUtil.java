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
package nl.minvenj.pef.pseudo.dump.cap;

import java.io.IOException;

import io.parsingdata.metal.data.ParseResult;
import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.serialize.Processor;

/**
 * Utility methods relevant to CAP file processing.
 *
 * @author Netherlands Forensic Institute.
 */
public final class CapUtil {

    private CapUtil() {
    }

    /**
     * Pseudonymizes parsed packet data contained in a structure containing packet data.
     * Returns the reconstructed structure with the new pseudonymized bytes.
     *
     * @param pseudonymizer the frame pseudonymizer with its transformers set to use for pseudonymization
     * @param result the record Metal parse result to extract packet data from
     * @return the rebuilt parsed bytes, with new pseudonymized packet data
     * @throws IOException when an I/O error occurs during parsing
     */
    public static byte[] getPseudonymizedStructureBytes(final FramePseudonymizer pseudonymizer, final ParseResult result) throws IOException {
        final PacketDataStructureSerializer structureSerializer = new PacketDataStructureSerializer();
        new Processor().process(result, structureSerializer);
        final byte[] packetData = structureSerializer.getPacketDataBytes();
        final byte[] pseudoPacketData = pseudonymizer.pseudonymize(packetData);
        final byte[] structureBytes = structureSerializer.outputData();
        System.arraycopy(pseudoPacketData, 0, structureBytes, (int) structureSerializer.getPacketDataOffset(), pseudoPacketData.length);
        return structureBytes;
    }
}
