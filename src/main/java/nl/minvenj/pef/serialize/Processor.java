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

import static nl.minvenj.pef.metal.GraphUtil.findSubGraph;

import java.util.ArrayList;
import java.util.List;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseItem;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.data.ParseValue;
import nl.minvenj.pef.serialize.constraint.TransformConstraint;
import nl.minvenj.pef.serialize.process.ParseValueProcessor;
import nl.minvenj.pef.serialize.transform.ConditionalTransformer;
import nl.minvenj.pef.serialize.transform.ParseValueTransformer;
import nl.minvenj.pef.util.Util;
import nl.minvenj.pef.metal.ValueUpdater;

/**
 *
 * Processes a Metal parse result with a provided ParseValue processor.
 *
 * Can apply various token transformers to change the parsegraph before processing.
 *
 * @author Netherlands Forensic Institute.
 */
public final class Processor {

    private final List<ConditionalTransformer> _transformers;

    public Processor() {
        _transformers = new ArrayList<>();
    }

    /**
     * Adds a new transformer to this processor.
     *
     * The constraint determines when a value should be transformed.
     * The fieldName determines what value should be transformed.
     * The transformer determines how the value should be transformed.
     *
     * @param constraint the constraint to apply
     * @param fieldName the name of the value to transform
     * @param transformer the transformer to transform the value with
     * @return this
     */
    public Processor addTransformer(final TransformConstraint constraint, final String fieldName, final ParseValueTransformer transformer) {
        final ConditionalTransformer transformModule = new ConditionalTransformer(
               Util.argNotNull("constraint", constraint),
               Util.argNotNull("fieldName", fieldName),
               Util.argNotNull("transformer", transformer));
        _transformers.add(transformModule);
        return this;
    }

    /**
     * Same as {@link #addTransformer(TransformConstraint, String, ParseValueTransformer)}, with
     * {@link TransformConstraint#TRUE} as the constraint.
     *
     * @param valueName the name of the value to transform
     * @param transformer the transformer to transform the value with
     * @return this
     */
    public Processor addTransformer(final String valueName, final ParseValueTransformer transformer) {
        return addTransformer(TransformConstraint.TRUE, valueName, transformer);
    }

    /**
     * Transforms and processes the parsed values in ParseResult using the provided ParseValue processor.
     *
     * @param result the result to transform and process
     * @param parseValueProcessor the processor to use
     */
    public void transformAndProcess(final ParseResult result, final ParseValueProcessor parseValueProcessor) {
        transformAndProcess(result.environment, parseValueProcessor);
    }

    /**
     * Processes all parsed values in ParseResult using the provided ParseValue processor.
     *
     * @param result the result to process
     * @param parseValueProcessor the processor to use
     */
    public void process(final ParseResult result, final ParseValueProcessor parseValueProcessor) {
        process(result.environment, parseValueProcessor);
    }
    /**
     * Processes all parsed values in the environment using the provided ParseValue processor.
     *
     * @param environment the environment to process
     * @param parseValueProcessor the processor to use
     */
    public void process(final Environment environment, final ParseValueProcessor parseValueProcessor) {
        process(parseValueProcessor, environment.order);
    }

    private void transformAndProcess(final Environment environment, final ParseValueProcessor parseValueProcessor) {
        Environment env = environment;
        for (final ConditionalTransformer transformer : _transformers) {
            env = updateEnv(env, transformer);
        }
        process(parseValueProcessor, env.order);
    }

    private void process(final ParseValueProcessor parseValueProcessor, final ParseGraph graph) {
        final ParseItem head = graph.head;
        if (head == null) {
            return;
        }
        if (head.isValue()) {
            parseValueProcessor.process(head.asValue());
        }
        else if (head.isGraph()) {
            process(parseValueProcessor, head.asGraph());
        }
        process(parseValueProcessor, graph.tail);
    }

    private Environment updateEnv(final Environment environment, final ConditionalTransformer transformer) {
        return updateEnv(environment.order, environment, transformer);
    }

    private Environment updateEnv(final ParseGraph graph, final Environment environment, final ConditionalTransformer transformer) {
        Environment newEnvironment = environment;
        final ParseItem head = graph.head;
        if (head == null) {
            return newEnvironment;
        }
        if (head.isValue()) {
            newEnvironment = transform(head.asValue(), newEnvironment, transformer);
        }
        if (head.isGraph()) {
            newEnvironment = updateEnv(head.asGraph(), newEnvironment, transformer);
        }
        return updateEnv(graph.tail, newEnvironment, transformer);
    }

    private Environment transform(final ParseValue value, final Environment environment, final ConditionalTransformer transformer) {
        Environment currentEnv = environment;
        ParseValue newValue = value;
        if (transformer.isApplicableFor(value)) {
            final ParseGraph subGraph = findSubGraph(environment, value, transformer.getTransformerContext());
            final Environment transformerEnvironment = new Environment(subGraph, environment.input, environment.offset);
            if (transformer.isSatisfiedBy(transformerEnvironment)) {
                newValue = transformer.transform(newValue, transformerEnvironment);
                currentEnv = ValueUpdater.updateEnv(currentEnv, newValue);
            }
        }
        return currentEnv;
    }
}