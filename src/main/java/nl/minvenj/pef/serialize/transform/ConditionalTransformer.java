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

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.serialize.constraint.TransformConstraint;

/**
 * A transformer module.
 *
 * Has a certain constraint attached to it. Transforming should only be done
 * when this is satisfied. The value to be transformed is determined by the fieldName.
 * A value matching this fieldName will be transformed.
 *
 * "*" as a fieldName will match each value.
 *
 * @author Netherlands Forensic Institute.
 */
public final class ConditionalTransformer {

    private final TransformConstraint _constraint;
    private final String _fieldName;
    private final ParseValueTransformer _transformer;

    /**
     * Initialize a new conditional transformer.
     *
     * @param constraint the constraint to check a certain environment with
     * @param fieldName the name of the field this transformer applies to
     * @param transformer the transformer to use for the transformation of the value
     */
    public ConditionalTransformer(final TransformConstraint constraint, final String fieldName, final ParseValueTransformer transformer) {
        _constraint = constraint;
        _fieldName = fieldName;
        _transformer = transformer;
    }

    /**
     * Check if an environment satisfies this conditional transformer.
     *
     * @param environment the environment to check the constraint on
     * @return true if the constraint is satisfied by the environment
     */
    public boolean isSatisfiedBy(final Environment environment) {
        return _constraint.isSatisfiedBy(environment);
    }

    /**
     * Check if this transformer applies to the ParseValue provided.
     *
     *  if the fieldName is defined as "*" the transformer is always applicable.
     *
     * @param value the ParseValue to check against
     * @return true if the ParseValue short name is equal to the fieldName given to this transformer, or if the fieldName is equal to "*"
     */
    public boolean isApplicableFor(final ParseValue value) {
        if (_fieldName.equals("*")) {
            return true;
        }
        return value.matches(_fieldName);
    }

    /**
     * Transform a value using this transformer.
     *
     * You should only call transform when isSatisfied for the environment
     * passed here returns true. Else, correct behavior is not guaranteed.
     *
     * (Also see {@link ParseValueTransformer#transform(ParseValue, Environment)}.)
     *
     * @param value the value to transform
     * @param environment the environment the transformer can use for its transformation of the value
     * @return a transformed value
     */
    public ParseValue transform(final ParseValue value, final Environment environment) {
        return _transformer.transform(value, environment);
    }

    /**
     * Get the context the transformer requires to operate.
     *
     * @return a token defining a context
     */
    public Token[] getTransformerContext() {
        return _transformer.context();
    }
}
