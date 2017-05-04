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
 * Used to extract ICMP header and payload bytes.
 *
 * Collects and returns a byte array containing the combined bytes of
 * the values starting from the "icmptype" offset.
 *
 * @author Netherlands Forensic Institute.
 */
public class ICMPHeaderPayloadSerializer implements ParseValueProcessor {

    private long _icmpOffset = -1;
    private final SortedMap<Long, byte[]> _data = new TreeMap<>();

    @Override
    public void process(final ParseValue value) {
        // ICMP starts at icmptype, so when we encounter it we save the offset
        if (_icmpOffset != -1 && value.matches("icmptype")) {
            _icmpOffset = value.getOffset();
        }
        // only data on or after icmptype offset should be collected
        if (value.getOffset() >= _icmpOffset) {
            _data.put(value.getOffset(), value.getValue());
        }
    }

    public byte[] outputData() {
        final SortedMap<Long, byte[]> icmpHeaderPayload = _data.tailMap(_icmpOffset);
        return Util.mergeBytes(icmpHeaderPayload.values());
    }
}
