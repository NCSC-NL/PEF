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

/**
 * Used to invert all bits of a value.
 *
 * @author Netherlands Forensic Institute.
 */
public class InvertBitTransformer implements ParseValueTransformer {

    private final Token[] _context;

    public InvertBitTransformer(final Token... context) {
        _context = context;
    }

    @Override
    public ParseValue transform(final ParseValue value, final Environment environment) {
        final byte[] data = value.getValue();
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (~data[i]);
        }
        return new ParseValue(value.name, value.getDefinition(), value.getOffset(), data, value.enc);
    }

    @Override
    public Token[] context() {
        return _context;
    }
}