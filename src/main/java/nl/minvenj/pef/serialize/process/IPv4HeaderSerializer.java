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
 * Used to extract the IPv4 header.
 *
 * Collects the header values and returns a byte array containing the
 * combined bytes of the values.
 *
 * @author Netherlands Forensic Institute.
 */
public class IPv4HeaderSerializer implements ParseValueProcessor {

    private long _headerStartOffset = -1;
    private long _headerEndOffset = -1;
    private final SortedMap<Long, byte[]> _data = new TreeMap<>();

    @Override
    public void process(final ParseValue value) {
        // on every match of versionihl, save the start and end offset of that IPv4 header
        if (value.matches("versionihl")) {
            _headerStartOffset = value.getOffset();
            final int headerSize = (value.asNumeric().intValue() & 0x0F) * 4;
            _headerEndOffset = _headerStartOffset + headerSize;
        }
        _data.put(value.getOffset(), value.getValue());
    }

    public byte[] outputData() {
        final SortedMap<Long, byte[]> headerDataMap = _data.tailMap(_headerStartOffset).headMap(_headerEndOffset);
        return Util.mergeBytes(headerDataMap.values());
    }
}
