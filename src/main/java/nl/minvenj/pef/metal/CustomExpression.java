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

import static io.parsingdata.metal.Util.checkNotNull;

import java.io.IOException;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.encoding.Encoding;
import io.parsingdata.metal.expression.Expression;
import io.parsingdata.metal.expression.comparison.ComparisonExpression;
import io.parsingdata.metal.expression.value.Value;
import io.parsingdata.metal.expression.value.ValueExpression;
import io.parsingdata.metal.token.Token;
import static io.parsingdata.metal.Shorthand.ref;
import static io.parsingdata.metal.Shorthand.last;

/**
 * Utility class containing custom expressions not contained in the Metal library (yet).
 *
 * @author Netherlands Forensic Institute.
 */
public final class CustomExpression {

    private CustomExpression() {
    }

    public static ComparisonExpression gtEqNum(final ValueExpression p) {
        return new GtEqNum(null, p);
    }

    public static ComparisonExpression gtEqNum(final ValueExpression c, final ValueExpression p) {
        return new GtEqNum(c, p);
    }

    public static Expression expFalse() {
        return new False();
    }

    public static Token enc(final Token t, final Encoding e) {
        return new EncodedToken(t, e);
    }

    /**
     * This class represents a &gt;= expression.
     *
     * @author Netherlands Forensic Institute.
     */
    public static class GtEqNum extends ComparisonExpression {

        public GtEqNum(final ValueExpression current, final ValueExpression predicate) {
            super(current, predicate);
        }

        @Override
        public boolean compare(final Value current, final Value predicate) {
            return current.asNumeric().compareTo(predicate.asNumeric()) >= 0;
        }
    }

    /**
     * This class represents a boolean false.
     *
     * @author Netherlands Forensic Institute.
     */
    public static class False implements Expression {

        @Override
        public boolean eval(final Environment env, final Encoding enc) {
            return false;
        }

        @Override
        public String toString() {
            return getClass().getSimpleName();
        }
    }

    /**
     * Token containing a token which should be interpreted in given encoding.
     *
     * @author Netherlands Forensic Institute.
     */
    public static class EncodedToken extends Token {

        private final Token _op;

        public EncodedToken(final Token op, final Encoding enc) {
            super(op.name, enc);
            _op = checkNotNull(op, "op");
        }

        @Override
        protected ParseResult parseImpl(final String scope, final Environment env, final Encoding enc) throws IOException {
            return _op.parse(scope, env, enc);
        }
    }

    /**
     * Get the last reference of a reference list.
     *
     * @param name the name to find in the token
     * @return the last reference of the list found
     */
    public static ValueExpression lastRef(final String name) {
        return last(ref(name));
    }
}
