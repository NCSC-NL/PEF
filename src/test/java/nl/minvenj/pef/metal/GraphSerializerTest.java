package nl.minvenj.pef.metal;

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

import static org.junit.Assert.assertArrayEquals;

import static io.parsingdata.metal.Shorthand.def;
import static io.parsingdata.metal.Shorthand.rep;
import static io.parsingdata.metal.Shorthand.seq;
import static io.parsingdata.metal.Shorthand.sub;
import static nl.minvenj.pef.metal.CustomExpression.lastRef;

import java.io.IOException;

import org.junit.Test;

import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.util.Util;

public class GraphSerializerTest {

    @Test
    public void simpleData() throws IOException {
        final Token SIMPLE_TOKEN = def("value", 1);
        final byte[] _simpleData = new byte[]{42};

        final GraphSerializer serializer = new GraphSerializer();

        final ParseResult simple = Util.parse(_simpleData, SIMPLE_TOKEN);
        serializer.serialize(simple.environment.order);

        assertArrayEquals(_simpleData, serializer.data());
    }

    @Test
    public void sequenceData() throws IOException {
        final Token SEQUENCE_TOKEN = rep(seq(def("value", 1), def("value2", 1)));
        final byte[] _sequenceData = new byte[]{42, 43, 44, 45};

        final GraphSerializer serializer = new GraphSerializer();

        final ParseResult sequence = Util.parse(_sequenceData, SEQUENCE_TOKEN);
        serializer.serialize(sequence.environment.order);

        assertArrayEquals(_sequenceData, serializer.data());
    }

    @Test
    public void subData() throws IOException {
        final Token SUB_TOKEN = seq(
                def("ptr1", 1),
                sub(seq(
                        def("value1", 1),
                        def("ptr2", 1),
                        sub(def("value2", 1),
                                lastRef("ptr2"))),
                        lastRef("ptr1")));
        final byte[] _subData = new byte[]{2, 84, 42, 1};

        final GraphSerializer serializer = new GraphSerializer();

        final ParseResult subResult = Util.parse(_subData, SUB_TOKEN);
        serializer.serialize(subResult.environment.order);

        assertArrayEquals(_subData, serializer.data());
    }
}
