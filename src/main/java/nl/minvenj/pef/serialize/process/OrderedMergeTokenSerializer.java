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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import io.parsingdata.metal.data.ParseValue;
import nl.minvenj.pef.util.Util;

/**
 * Used to merge values in order of offset together.
 *
 * @author Netherlands Forensic Institute.
 */
public class OrderedMergeTokenSerializer implements ParseValueProcessor {

    private final List<ParseValue> _values = new ArrayList<>();

    @Override
    public void process(final ParseValue value) {
        _values.add(value);
    }

    public byte[] outputData() {
        Collections.sort(_values, new Comparator<ParseValue>() {
            @Override
            public int compare(final ParseValue o1, final ParseValue o2) {
                return Long.compare(o1.getOffset(), o2.getOffset());
            }
        });

        final List<byte[]> result = new ArrayList<>(_values.size());
        for (final ParseValue value : _values) {
            result.add(value.getValue());
        }

        return Util.mergeBytes(result);
    }
}
