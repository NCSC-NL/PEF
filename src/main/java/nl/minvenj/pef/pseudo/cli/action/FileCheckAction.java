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

import java.io.File;
import java.util.Map;

import net.sourceforge.argparse4j.inf.Argument;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;

/**
 * Custom Argparse4j action which checks if a given file, created from a file path argument,
 * exists and is a file.
 *
 * @author Netherlands Forensic Institute.
 */
public class FileCheckAction extends DefaultConsumeAction {

    @Override
    public void run(final ArgumentParser parser, final Argument arg, final Map<String, Object> attrs, final String flag, final Object value) throws ArgumentParserException {
        final File file = new File(value.toString());
        if (!file.isFile()) {
            throw new ArgumentParserException("cannot find file " + file, parser, arg);
        }

        attrs.put(arg.getDest(), value);
    }
}
