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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import static io.parsingdata.metal.Shorthand.con;
import static io.parsingdata.metal.Shorthand.def;
import static io.parsingdata.metal.Shorthand.repn;
import static io.parsingdata.metal.Shorthand.seq;
import static io.parsingdata.metal.Shorthand.str;

import java.io.IOException;

import org.junit.Test;

import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.data.ParseValueList;
import io.parsingdata.metal.data.selection.ByName;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.metal.GraphUtil;
import nl.minvenj.pef.util.Util;

public class GraphUtilTest {
    private static final Token DEF1 = def("value", 1);
    private static final Token INNER1 = str("INNER1", DEF1);

    private static final Token DEF2 = def("value", 1);
    private static final Token INNER2 = str("INNER2", DEF2);

    private static final Token OUTER = str("OUTER", seq(INNER1, INNER2));

    private static final Token REP_DEF = def("value", 1);
    private static final Token REPN = str("REPN", repn(REP_DEF, con(4)));

    @Test
    public void testSubGraphForSingleToken() throws IOException {
        final ParseResult result = Util.parse(new byte[]{0, 1}, OUTER);

        final ParseValue value1 = result.environment.order.get(DEF1).asValue();
        final ParseGraph subEnvironment1 = GraphUtil.findSubGraph(result.environment, value1, INNER1);
        assertThat(subEnvironment1.getDefinition(), is(equalTo(INNER1)));

        final ParseValue value2 = result.environment.order.get(DEF2).asValue();
        final ParseGraph subEnvironment2 = GraphUtil.findSubGraph(result.environment, value2, INNER2);
        assertThat(subEnvironment2.getDefinition(), is(equalTo(INNER2)));

        final ParseGraph subEnvironment3 = GraphUtil.findSubGraph(result.environment, value1, OUTER);
        assertThat(subEnvironment3.getDefinition(), is(equalTo(OUTER)));
    }

    @Test
    public void testRepn() throws IOException {
        final ParseResult result = Util.parse(new byte[]{0, 1, 2, 3}, REPN);

        ParseValueList values = ByName.getAllValues(result.environment.order, "value");
        while (values.head != null) {
            final ParseGraph subEnvironment = GraphUtil.findSubGraph(result.environment, values.head, REPN);
            assertThat(subEnvironment.getDefinition(), is(equalTo(REPN)));
            values = values.tail;
        }
    }

    @Test
    public void testSubGraphForMultipleTokens() throws IOException {
        final ParseResult result = Util.parse(new byte[]{0, 1}, OUTER);

        assertTrue(GraphUtil.containsDefinitions(result.environment.order, OUTER, INNER1));
        assertTrue(GraphUtil.containsDefinitions(result.environment.order, OUTER, INNER2));
    }

    @Test
    public void testDuplicateInnerToken() throws IOException {
        final ParseResult result = Util.parse(new byte[]{0, 1}, OUTER);

        assertFalse(GraphUtil.containsDefinitions(result.environment.order, INNER1, INNER1));
    }

    @Test
    public void testDuplicateOuterToken() throws IOException {
        final ParseResult result = Util.parse(new byte[]{0, 1}, OUTER);

        assertFalse(GraphUtil.containsDefinitions(result.environment.order, OUTER, OUTER));
    }

    @Test
    public void testIllegallyNestedTokens() throws IOException {
        final ParseResult result = Util.parse(new byte[]{0, 1}, OUTER);

        assertFalse(GraphUtil.containsDefinitions(result.environment.order, INNER1, INNER2));
    }

    @Test
    public void testSearchingInEmptyGraph() throws IOException {
        assertFalse(GraphUtil.containsDefinitions(ParseGraph.EMPTY, INNER1));
    }
}
