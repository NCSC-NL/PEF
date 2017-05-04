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
package nl.minvenj.pef.serialize.transform;

import static org.junit.Assert.assertArrayEquals;

import static io.parsingdata.metal.Shorthand.def;
import static io.parsingdata.metal.Shorthand.repn;
import static io.parsingdata.metal.Shorthand.seq;
import static io.parsingdata.metal.Shorthand.str;
import static nl.minvenj.pef.metal.CustomExpression.lastRef;
import static nl.minvenj.pef.util.Util.tokens;

import java.io.IOException;

import nl.minvenj.pef.serialize.Processor;
import org.junit.Test;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.data.ParseValueList;
import io.parsingdata.metal.data.selection.ByName;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.serialize.constraint.TransformConstraint;
import nl.minvenj.pef.serialize.process.CopyTokenSerializer;
import nl.minvenj.pef.util.Util;

public class SumTransformerTest {

    private static final Token VAL = str("VAL", def("value", 1));
    private static final Token SUM = str("SUM", def("sum", 1));
    private static final Token EXPR = str("EXPR", seq(
                                                      def("valcount", 1), // needed in order to find the correct scope
                                                      repn(VAL, lastRef("valcount")),
                                                      SUM));

    @Test
    public void testSum() throws IOException {
        final byte[] inputData = {3, 1, 2, 3, 0};

        final ParseResult result = Util.parse(inputData, EXPR);
        final CopyTokenSerializer tokenSerializer = new CopyTokenSerializer(inputData.length);

        new Processor()
            .addTransformer(new TransformConstraint(SUM), "sum", new SumTransformer())
            .transformAndProcess(result, tokenSerializer);

        final byte[] outputData = tokenSerializer.outputData();

        assertArrayEquals(new byte[]{3, 1, 2, 3, 6}, outputData);
    }

    static class SumTransformer implements ParseValueTransformer {

        @Override
        public Token[] context() {
            return tokens(EXPR);
        }

        @Override
        public ParseValue transform(final ParseValue value, final Environment environment) {
            ParseValueList values = ByName.getAllValues(environment.order, "value");
            byte sum = 0;
            while (values.head != null) {
                sum += values.head.getValue()[0];
                values = values.tail;
            }
            return new ParseValue(value.name, value.getDefinition(), value.getOffset(), new byte[]{sum}, value.enc);
        }
    }
}
