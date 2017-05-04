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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.sourceforge.argparse4j.inf.Argument;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;

/**
 * Custom Argparse4j action which checks the values of the checksum parameter.
 *
 * The value of the checksum parameter is a comma-separated list of protocol names,
 * it will be handles as such. It can also be a single value, namely "all", representing
 * all protocols.
 *
 * @author Netherlands Forensic Institute.
 */
public class ChecksumCheckAction extends DefaultConsumeAction {

    @Override
    public void run(final ArgumentParser parser, final Argument arg, final Map<String, Object> attrs, final String flag, final Object value) throws ArgumentParserException {
        @SuppressWarnings("unchecked")
        final String paramValues = ((List<String>) value).get(0);
        final Set<String> unique = new HashSet<>(Arrays.asList(paramValues.split(",")));
        final String[] protocols = unique.toArray(new String[unique.size()]);

        if (!(protocols.length == 1 && protocols[0].equals("all"))) {
            for (final String protocol : protocols) {
                if (!(protocol.equals("ipv4") || protocol.equals("udp") || protocol.equals("icmp"))) {
                    throw new ArgumentParserException("invalid protocol: " + protocol, parser, arg);
                }
            }
        }

        attrs.put(arg.getDest(), new ArrayList<String>(Arrays.asList(protocols)));
    }
}
