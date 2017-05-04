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
package nl.minvenj.pef.serialize.transform.pseudonymize;

import static nl.minvenj.pef.util.Util.tokens;

import java.security.InvalidKeyException;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseValue;
import io.parsingdata.metal.token.Token;
import nl.minvenj.pef.metal.packet.internet.IPv4;
import nl.minvenj.pef.pseudo.IPPseudonymizer;
import nl.minvenj.pef.serialize.transform.ParseValueTransformer;

/**
 * Used for encrypting IPv4 addresses.
 *
 * @author Netherlands Forensic Institute.
 */
public class IPv4AddressPseudonymizer implements ParseValueTransformer {

    private final IPPseudonymizer _pseudonymizer;

    public IPv4AddressPseudonymizer(final String key, final int mask) throws InvalidKeyException {
        _pseudonymizer = IPPseudonymizer.initIPv4Pseudonymizer(key, mask);
    }

    @Override
    public Token[] context() {
        return tokens(IPv4.FORMAT);
    }

    @Override
    public ParseValue transform(final ParseValue value, final Environment environment) {
        return new ParseValue(value.name, value.getDefinition(), value.getOffset(), _pseudonymizer.pseudonymize(value.getValue()), value.enc);
    }
}
