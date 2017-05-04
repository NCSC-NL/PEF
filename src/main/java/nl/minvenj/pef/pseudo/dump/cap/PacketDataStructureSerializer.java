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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import io.parsingdata.metal.data.ParseValue;
import nl.minvenj.pef.serialize.process.ParseValueProcessor;
import nl.minvenj.pef.util.Util;

/**
 * Collects fields of structures containing a "packetdata" field.
 *
 * This processor processes values contained in a parse result from a
 * Metal parse of this structure. The processor can be used to get and locate the "packetdata" bytes.
 *
 * @author Netherlands Forensic Institute.
 */
public class PacketDataStructureSerializer implements ParseValueProcessor {

    private long _startOffset = Long.MAX_VALUE;
    private final List<ParseValue> _blockFields = new ArrayList<>();
    private ParseValue _packetData;

    @Override
    public void process(final ParseValue value) {
        if (value.matches("packetdata")) {
            _packetData = value;
        }
        _blockFields.add(value);
        if (value.getOffset() < _startOffset) {
            _startOffset = value.getOffset();
        }
    }

    /**
     * Returns the packet data contained in the structure.
     *
     * These represent the bytes of a captured ethernet frame.
     *
     * @return the "packetdata" bytes
     */
    public byte[] getPacketDataBytes() {
        return _packetData.getValue();
    }

    /**
     * Returns the packet data offset inside the structure.
     *
     * @return the "packetdata" offset
     */
    public long getPacketDataOffset() {
        return _packetData.getOffset() - _startOffset;
    }

    /**
     * Returns the bytes of the recreated structure.
     *
     * @return the bytes of the structure
     */
    public byte[] outputData() {
        Collections.sort(_blockFields, new Comparator<ParseValue>() {
            @Override
            public int compare(final ParseValue o1, final ParseValue o2) {
                return Long.compare(o1.getOffset(), o2.getOffset());
            }
        });
        final List<byte[]> result = new ArrayList<>(_blockFields.size());
        for (final ParseValue value : _blockFields) {
            result.add(value.getValue());
        }
        return Util.mergeBytes(result);
    }
}
