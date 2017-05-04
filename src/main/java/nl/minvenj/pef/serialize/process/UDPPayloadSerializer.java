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
package nl.minvenj.pef.serialize.process;

import java.util.SortedMap;
import java.util.TreeMap;

import io.parsingdata.metal.data.ParseValue;
import nl.minvenj.pef.util.Util;

/**
 * Used to extract UDP payload bytes.
 *
 * Collects and returns a byte array containing the combined bytes of
 * the values starting after the UDP checksum offset.
 *
 * @author Netherlands Forensic Institute.
 */
public class UDPPayloadSerializer implements ParseValueProcessor {

    private long _udpDataOffset = -1;
    private final SortedMap<Long, byte[]> _data = new TreeMap<>();

    @Override
    public void process(final ParseValue value) {
        // UDP payload starts right after UDP checksum, so when we encounter it we save the offset
        if (value.matches("udpchecksum")) {
            _udpDataOffset = value.getOffset() + 2;
        }
        // only data after the UDP checksum offset should be collected
        if (value.getOffset() >= _udpDataOffset) {
            _data.put(value.getOffset(), value.getValue());
        }
    }

    public byte[] outputData() {
        final SortedMap<Long, byte[]> udpDataMap = _data.tailMap(_udpDataOffset);
        return Util.mergeBytes(udpDataMap.values());
    }
}
