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

import static io.parsingdata.metal.data.ParseGraph.EMPTY;
import static nl.minvenj.pef.util.Util.argNotNull;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.token.Token;

/**
 * Utility class used for locating and validating graphs.
 *
 * @author Netherlands Forensic Institute.
 */
public final class GraphUtil {

    private GraphUtil() {
    }

    /**
     * Locate the smallest sub-graph that satisfies the given constraints.
     *
     * Constraints are:
     * - The graph should contain the given value
     * - The graph's path from the root to the value should contain the given token definitions
     *
     * If the final token definition appears multiple times in the path from the root of the graph
     * to the located value, the smallest sub-graph nearest to the value is returned.
     *
     * @param environment the environment containing the graph to search in
     * @param value the value to search for
     * @param definitions the token definitions that should be present in the path from the root of the graph to the value
     * @return the found sub-graph, or an empty graph if the constraints could not be met
     */
    public static ParseGraph findSubGraph(final Environment environment, final ParseValue value, final Token... definitions) {
        argNotNull("environment", environment);
        argNotNull("value", value);
        argNotNull("definitions", definitions);

        final ArrayDeque<Token> tokenDeque = new ArrayDeque<>(Arrays.asList(definitions));
        return locateSubGraph(environment.order, value, tokenDeque);
    }

    /**
     * Check if a graph contains the given definitions, in order.
     *
     * @param graph the graph to search in
     * @param definitions the definitions to search for
     * @return <code>true</code> if all definitions were found, in order, <code>false</code> otherwise
     */
    public static boolean containsDefinitions(final ParseGraph graph, final Token... definitions) {
        argNotNull("graph", graph);
        argNotNull("definitions", definitions);

        if (definitions.length == 0) {
            return true;
        }

        final Deque<Token> definitionDeque = new ArrayDeque<>(Arrays.asList(definitions));
        final ParseGraph result = locateSubGraph(graph, null, definitionDeque);

        return result != ParseGraph.EMPTY;
    }

    private static ParseGraph locateSubGraph(final ParseGraph graph, final ParseValue value, final Deque<Token> definitions) {
        return locateSubGraph(graph, value, definitions, definitions.peekLast(), EMPTY);
    }

    private static ParseGraph locateSubGraph(final ParseGraph graph, final ParseValue value, final Deque<Token> definitions, final Token terminator, final ParseGraph result) {
        if (graph == EMPTY || graph.head == null) {
            return EMPTY;
        }

        final Token currentDefinition = graph.getDefinition();
        if (!definitions.isEmpty() && currentDefinition == definitions.peekFirst()) {
            // found a token in the path
            definitions.removeFirst();
        }

        ParseGraph resultGraph = result;
        if (definitions.isEmpty() && currentDefinition == terminator) {
            // found a deeper token matching the terminating token in the path (making the sub-graph smaller)
            resultGraph = graph;

            // in case we're not searching for a value at all, return immediately
            if (value == null) {
                return resultGraph;
            }
        }

        if (graph.head.isValue() && graph.head.asValue() == value && definitions.isEmpty()) {
            return resultGraph;
        }
        if (graph.head.isGraph()) {
            final ParseGraph headResult = locateSubGraph(graph.head.asGraph(), value, new ArrayDeque<>(definitions), terminator, resultGraph);
            if (headResult != EMPTY) {
                return headResult;
            }
        }
        return locateSubGraph(graph.tail, value, definitions, terminator, resultGraph);
    }
}
