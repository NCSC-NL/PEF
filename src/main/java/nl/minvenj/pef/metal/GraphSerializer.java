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
package nl.minvenj.pef.metal;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseItem;
import io.parsingdata.metal.data.ParseValue;
import nl.minvenj.pef.util.Util;

/**
 * Utility class for serialization of a ParseGraph.
 *
 * @author Netherlands Forensic Institute.
 */
public class GraphSerializer {

    private final List<ParseValue> _parseValues = new ArrayList<>();

    /**
     * Recursive function that serializes a (sub)ParseGraph.
     *
     * @param graph the graph to serialize
     */
    public void serialize(final ParseGraph graph) {
        final ParseItem head = graph.head;
        if (head == null) {
            return;
        }
        if (head.isValue()) {
            serialize(head.asValue());
        }
        else if (head.isGraph()) {
            serialize(head.asGraph());
        }
        serialize(graph.tail);
    }

    /**
     * Stores the found ParseValue in the graph.
     *
     * @param value the value that will be stored for serialization
     */
    private void serialize(final ParseValue value) {
        _parseValues.add(value);
    }

    /**
     * Orders all collected parseValues within the ParseGraph based on offset and merges the bytes
     * to a byte array.
     *
     * @return the merged byte array
     */
    public byte[] data() {
        List<ParseValue> copyList = new ArrayList(_parseValues);
        Collections.sort(copyList, new Comparator<ParseValue>() {
            @Override
            public int compare(final ParseValue o1, final ParseValue o2) {
                return Long.compare(o1.getOffset(), o2.getOffset());
            }
        });

        final List<byte[]> result = new ArrayList<>(copyList.size());
        for (final ParseValue value : copyList) {
            result.add(value.getValue());
        }
        return Util.mergeBytes(result);
    }

    /**
     * A utility function to get a copy of the list of parsevalues.
     *
     * @return a list of parseValues
     */
    public List<ParseValue> getGraphValues() {
        return new ArrayList<ParseValue>(_parseValues);
    }
}
