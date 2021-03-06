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
package nl.minvenj.pef.serialize;

import static org.junit.Assert.assertArrayEquals;

import static io.parsingdata.metal.Shorthand.def;
import static io.parsingdata.metal.Shorthand.seq;
import static io.parsingdata.metal.Shorthand.str;

import java.io.IOException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.serialize.constraint.TransformConstraint;
import nl.minvenj.pef.serialize.process.CopyTokenSerializer;
import nl.minvenj.pef.serialize.transform.InvertBitTransformer;
import nl.minvenj.pef.serialize.transform.ParseValueTransformer;
import nl.minvenj.pef.util.Util;

public class TransformSerializerTest {

    @Rule
    public ExpectedException _thrown = ExpectedException.none();

    private static final Token INNER1 = str("INNER1", def("value", 1));
    private static final Token INNER2 = str("INNER2", def("value", 1));
    private static final Token OUTER = str("OUTER", seq(INNER1, INNER2));

    // unused in actual parsing
    private static final Token INNER3 = str("INNER3", def("value", 1));

    public ParseValueTransformer invertBits(final Token context) {
        return new InvertBitTransformer(context);
    }

    @Test
    public void testInvertInner1() throws IOException {
        final byte[] inputData = {0, 1};

        final ParseResult result = Util.parse(inputData, OUTER);
        final CopyTokenSerializer tokenSerializer = new CopyTokenSerializer(inputData.length);

        new Processor()
            .addTransformer(new TransformConstraint(INNER1), "value", invertBits(INNER1))
            .transformAndProcess(result, tokenSerializer);
        final byte[] outputData = tokenSerializer.outputData();

        // do not transform second value
        assertArrayEquals(new byte[]{-1, 1}, outputData);
    }

    @Test
    public void testInvertInner2() throws IOException {
        final byte[] inputData = {0, 1};

        final ParseResult result = Util.parse(inputData, OUTER);
        final CopyTokenSerializer tokenSerializer = new CopyTokenSerializer(inputData.length);

        new Processor()
            .addTransformer(new TransformConstraint(INNER2), "value", invertBits(INNER2))
            .transformAndProcess(result, tokenSerializer);
        final byte[] outputData = tokenSerializer.outputData();

        // do not transform second value
        assertArrayEquals(new byte[]{0, -2}, outputData);
    }

    @Test
    public void testInvertOuter() throws IOException {
        final byte[] inputData = {0, 1};

        final ParseResult result = Util.parse(inputData, OUTER);
        final CopyTokenSerializer tokenSerializer = new CopyTokenSerializer(inputData.length);

        new Processor()
            .addTransformer(new TransformConstraint(OUTER), "value", invertBits(OUTER))
            .transformAndProcess(result, tokenSerializer);
        final byte[] outputData = tokenSerializer.outputData();

        // both values are transformed
        assertArrayEquals(new byte[]{-1, -2}, outputData);
    }

    @Test
    public void testNothingTransforms() throws IOException {
        final byte[] inputData = {0, 1};

        final ParseResult result = Util.parse(inputData, OUTER);
        final CopyTokenSerializer tokenSerializer = new CopyTokenSerializer(inputData.length);

        new Processor()
            .addTransformer(new TransformConstraint(OUTER, INNER3), "value", invertBits(INNER3))
            .transformAndProcess(result, tokenSerializer);
        final byte[] outputData = tokenSerializer.outputData();

        assertArrayEquals(new byte[]{0, 1}, outputData);
    }

    @Test
    public void nullConstraint() throws IOException {
        final byte[] inputData = {0, 1};

        final ParseResult result = Util.parse(inputData, OUTER);
        final CopyTokenSerializer tokenSerializer = new CopyTokenSerializer(inputData.length);

        _thrown.expect(IllegalArgumentException.class);
        _thrown.expectMessage("Argument 'constraint' cannot be null!");

        new Processor()
            .addTransformer(null, "value", invertBits(INNER1))
            .transformAndProcess(result, tokenSerializer);
    }

    @Test
    public void nullFieldName() throws IOException {
        final byte[] inputData = {0, 1};

        final ParseResult result = Util.parse(inputData, OUTER);
        final CopyTokenSerializer tokenSerializer = new CopyTokenSerializer(inputData.length);

        _thrown.expect(IllegalArgumentException.class);
        _thrown.expectMessage("Argument 'fieldName' cannot be null!");

        new Processor()
            .addTransformer(new TransformConstraint(OUTER, INNER1), null, invertBits(INNER1))
            .transformAndProcess(result, tokenSerializer);
    }

    @Test
    public void nullTransformator() throws IOException {
        final byte[] inputData = {0, 1};

        final ParseResult result = Util.parse(inputData, OUTER);
        final CopyTokenSerializer tokenSerializer = new CopyTokenSerializer(inputData.length);

        _thrown.expect(IllegalArgumentException.class);
        _thrown.expectMessage("Argument 'transformer' cannot be null!");

        new Processor()
            .addTransformer(new TransformConstraint(OUTER, INNER1), "value", null)
            .transformAndProcess(result, tokenSerializer);
    }
}
