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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import static io.parsingdata.metal.Shorthand.con;
import static io.parsingdata.metal.Shorthand.def;
import static io.parsingdata.metal.Shorthand.nod;
import static io.parsingdata.metal.Shorthand.seq;
import static io.parsingdata.metal.Shorthand.sub;
import static io.parsingdata.metal.data.ParseGraph.NONE;
import static nl.minvenj.pef.metal.CustomExpression.lastRef;
import static nl.minvenj.pef.util.TestUtil.equalTo;

import java.io.IOException;

import org.junit.Test;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseGraphList;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.data.selection.ByName;
import io.parsingdata.metal.encoding.Encoding;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.metal.ValueUpdater;
import nl.minvenj.pef.util.Util;

public class ValueUpdaterTest {

    private static final Token NO_DEFINITION = NONE;

    @Test
    public void testEnvSingle() throws IOException {
        final Token token = def("value", 1);
        final byte[] bytes = new byte[]{1};
        final ParseResult result = Util.parse(bytes, token);

        final Environment originalEnvironment = result.environment;
        final ParseValue valueToUpdate = originalEnvironment.order.get("value");

        final Environment newEnvironment = ValueUpdater.updateEnv(originalEnvironment, new ParseValue("value", token, 0, new byte[]{2}, new Encoding()));
        final ParseValue newValue = newEnvironment.order.get("value");

        assertThat(valueToUpdate.asNumeric().intValue(), is(equalTo(1)));
        assertThat(newValue.asNumeric().intValue(), is(equalTo(2)));
    }

    @Test
    public void testGraphSingle() throws IOException {
        final ParseGraph graph = ParseGraph.EMPTY.add(new ParseValue("value", NO_DEFINITION, 0, new byte[]{1}, new Encoding()));
        final ParseValue originalValue = graph.head.asValue();

        final ParseGraph updated = ValueUpdater.updateGraph(new ParseValue("value", NO_DEFINITION, 0, new byte[]{2}, new Encoding()), graph);
        final ParseValue newValue = updated.head.asValue();

        assertThat(originalValue.asNumeric().intValue(), is(equalTo(1)));
        assertThat(newValue.asNumeric().intValue(), is(equalTo(2)));
    }

    @Test
    public void testEnvSeq() throws IOException {
        final Token valueFour = def("valueFour", 4);
        final Token token = seq(def("valueOne", 1), def("valueTwo", 2), def("valueThree", 3), valueFour, def("valueFive", 5));
        final byte[] bytes = new byte[]{1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5};
        final ParseResult result = Util.parse(bytes, token);

        assertTrue(result.succeeded);
        final Environment originalEnvironment = result.environment;
        final ParseValue valueToUpdate = ByName.getValue(originalEnvironment.order, "valueFour");

        final Environment newEnvironment = ValueUpdater.updateEnv(originalEnvironment, new ParseValue("valueFour", valueFour, 6, new byte[4], new Encoding()));
        final ParseValue newValue = newEnvironment.order.get("valueFour");

        assertThat(newEnvironment.order.size, is(equalTo(originalEnvironment.order.size)));
        assertThat(valueToUpdate.getValue(), is(equalTo(new byte[]{4, 4, 4, 4})));
        assertThat(newValue.getValue(), is(equalTo(new byte[]{0, 0, 0, 0})));
    }

    @Test
    public void testEnvSub() throws IOException {
        final Token token = seq(
                                def("ptr1", 1),
                                sub(seq(
                                        def("ptr2", 1),
                                        sub(def("value", 1),
                                            lastRef("ptr2"))),
                                    lastRef("ptr1")));

        final byte[] bytes = new byte[]{2, 42, 1};
        final ParseResult result = Util.parse(bytes, token);
        final Environment originalEnvironment = result.environment;
        final ParseValue valueToUpdate = originalEnvironment.order.get("value");

        final Environment newEnvironment = ValueUpdater.updateEnv(originalEnvironment,
                                                                  new ParseValue(valueToUpdate.name,
                                                                                 token,
                                                                                 valueToUpdate.getOffset(),
                                                                                 new byte[]{43},
                                                                                 valueToUpdate.enc));
        final ParseValue newValue = newEnvironment.order.get("value");

        assertThat(valueToUpdate.getValue(), is(equalTo(new byte[]{42})));
        assertThat(newValue.getValue(), is(equalTo(new byte[]{43})));
        assertThat(newEnvironment.order.size, is(equalTo(originalEnvironment.order.size)));
    }

    @Test
    public void testsEnvRefValueExpr() throws IOException {
        final Token footer = def("footer", 1);
        final Token token = seq(
                                def("size", 1),
                                def("data", lastRef("size")),
                                footer,
                                def("terminator", 1));

        final byte[] bytes = new byte[]{2, 14, 15, 3, 0};
        final ParseResult result = Util.parse(bytes, token);
        final Environment originalEnvironment = result.environment;
        final ParseValue valueToUpdate = originalEnvironment.order.get("footer");

        final Environment newEnvironment = ValueUpdater.updateEnv(originalEnvironment,
                                                                  new ParseValue(valueToUpdate.name,
                                                                                 footer,
                                                                                 valueToUpdate.getOffset(),
                                                                                 new byte[]{16},
                                                                                 valueToUpdate.enc));
        final ParseValue newValue = newEnvironment.order.get("footer");

        assertThat(valueToUpdate.getValue(), is(equalTo(new byte[]{3})));
        assertThat(newValue.getValue(), is(equalTo(new byte[]{16})));
        assertThat(newEnvironment.order.size, is(equalTo(originalEnvironment.order.size)));
    }

    @Test
    public void testGraphlastRef() throws IOException {
        final Token value = def("value", 1);
        final Token repeated = seq(
                                   def("ptr", 1),
                                   sub(
                                       value,
                                       lastRef("ptr")));
        final Token subs = seq(
                               def("ptr1", 1),
                               sub(
                                   repeated,
                                   lastRef("ptr1")),
                               nod(con(2)),
                               def("ptr2", 1),
                               sub(
                                   repeated,
                                   lastRef("ptr2")));

        final byte[] bytes = new byte[]{2, 42, 1, 1};
        final ParseResult result = Util.parse(bytes, subs);
        final Environment originalEnvironment = result.environment;
        final ParseValue valueToUpdate = originalEnvironment.order.get("value");

        final Environment newEnvironment = ValueUpdater.updateEnv(originalEnvironment,
                                                                  new ParseValue(valueToUpdate.name,
                                                                                 value,
                                                                                 valueToUpdate.getOffset(),
                                                                                 new byte[]{43},
                                                                                 valueToUpdate.enc));
        final ParseValue newValue = newEnvironment.order.get("value");

        assertThat(valueToUpdate.getValue(), is(equalTo(new byte[]{42})));
        assertThat(newValue.getValue(), is(equalTo(new byte[]{43})));
        assertThat(newEnvironment.order.size, is(equalTo(originalEnvironment.order.size)));
    }

    @Test
    public void testGraphRefBigOffset() throws IOException {
        final Token value = def("value", 1);
        final Token repeated = seq(
                                   def("ptr", 1),
                                   sub(
                                       value,
                                       lastRef("ptr")));
        final Token subs = seq(
                               def("data", 10),
                               def("ptr1", 1),
                               sub(
                                   repeated,
                                   lastRef("ptr1")),
                               nod(con(2)),
                               def("ptr2", 1),
                               sub(
                                   repeated,
                                   lastRef("ptr2")),
                               def("data", 10));

        final byte[] bytes = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 42, 11, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        final ParseResult result = Util.parse(bytes, subs);
        final Environment originalEnvironment = result.environment;
        final ParseValue valueToUpdate = originalEnvironment.order.get("value");

        final Environment newEnvironment = ValueUpdater.updateEnv(originalEnvironment,
                                                                  new ParseValue(valueToUpdate.name,
                                                                                 value,
                                                                                 valueToUpdate.getOffset(),
                                                                                 new byte[]{42},
                                                                                 valueToUpdate.enc));
        final ParseValue newValue = newEnvironment.order.get("value");

        assertThat(valueToUpdate.getValue(), is(equalTo(new byte[]{42})));
        assertThat(newValue.getValue(), is(equalTo(new byte[]{42})));
        assertThat(newEnvironment.order.size, is(equalTo(originalEnvironment.order.size)));

        final ParseGraphList originalRefs = originalEnvironment.order.getRefs();
        final ParseGraphList newRefs = newEnvironment.order.getRefs();

        assertThat(newRefs.head.head.asValue(), is(equalTo(originalRefs.head.head.asValue())));
        assertThat(newRefs.tail.head, is(equalTo(originalRefs.tail.head)));
    }
}
