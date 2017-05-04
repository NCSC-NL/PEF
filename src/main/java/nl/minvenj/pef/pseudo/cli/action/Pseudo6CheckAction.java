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
package nl.minvenj.pef.pseudo.cli.action;

import java.util.List;
import java.util.Map;

import net.sourceforge.argparse4j.inf.Argument;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import nl.minvenj.pef.util.Util;

/**
 * Custom Argparse4j action which checks the values of the IPv6 pseudonymization parameter.
 *
 * It checks if the passed values for the key and mask are valid.
 *
 * @author Netherlands Forensic Institute.
 */
public class Pseudo6CheckAction extends DefaultConsumeAction {

    @Override
    public void run(final ArgumentParser parser, final Argument arg,
                    final Map<String, Object> attrs, final String flag, final Object value) throws ArgumentParserException {
        @SuppressWarnings("unchecked")
        final List<String> values = (List<String>) value;

        final String key = values.get(0);
        if (key.length() != 32 || !Util.stringNumInRadix(key, 16)) {
            throw new ArgumentParserException("AES key must be a 32 character hexidecimal string (128-bit)", parser, arg);
        }

        final String maskString = values.get(1);
        final String maskValueString = maskString.substring(1);

        if (!maskString.startsWith("/") || !Util.stringNumInRadix(maskValueString, 10)) {
            throw new ArgumentParserException("IPv6 mask must be an integer prefixed with /", parser, arg);
        }

        final int mask = Integer.parseInt(maskValueString);
        if (mask < 0 || mask > 120) {
            throw new ArgumentParserException("IPv6 mask must be in range [0, 120]", parser, arg);
        }

        attrs.put(arg.getDest(), value);
    }
}
