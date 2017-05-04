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
package nl.minvenj.pef.pseudo.cli;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;

import java.io.IOException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.SystemErrRule;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import nl.minvenj.pef.Settings;

@RunWith(Parameterized.class)
public class CLToolParameterTest {

    @Rule
    public final SystemErrRule _err = new SystemErrRule().enableLog().muteForSuccessfulTests();

    @Parameter(0)
    public String _args;

    @Parameter(1)
    public String _output;

    @Parameters(name = "args: {0} - output: {1}")
    public static Object[][] data() throws IOException {

        final String basePath = Settings.getTestBasePath();
        final String newFile = basePath + "/dummy.pcap";

        return new Object[][]{
            {" ", "outfile is required"},
            {"-o out", "infile is required"},
            {"-4", "argument -4/--pseudo4: expected 2 argument(s)"},
            {"-4 123 /2", "argument -4/--pseudo4: AES key must be a 32 character hexidecimal string (128-bit)"},
            {"-4 0123456789ABCDEF0123456789ABCDEF /25", "argument -4/--pseudo4: IPv4 mask must be in range [0, 24]"},
            {"-4 0123456789ABCDEF0123456789ABCDEF 10", "mask must be an integer prefixed with /"},
            {"-6 ", "argument -6/--pseudo6: expected 2 argument(s)"},
            {"-6 123 /4", "argument -6/--pseudo6: AES key must be a 32 character hexidecimal string (128-bit)"},
            {"-6 0123456789ABCDEF0123456789ABCDEF /222", "argument -6/--pseudo6: IPv6 mask must be in range [0, 120]"},
            {"-6 0123456789ABCDEF0123456789ABCDEF 1", "mask must be an integer prefixed with /"},
            {"-i " + basePath + "/pcaps/magiconly.pcap -o out -c foo", "argument -c/--checksum: invalid protocol: foo"},
            {"-i " + basePath + "/pcaps/magiconly.pcap -o out -c udp,bar,ipv4", "argument -c/--checksum: invalid protocol: bar"},
            {basePath + "/pcaps/1dnsidentical.pcap " + newFile + " -c all", ""},
            {"-c", "argument -c/--checksum: expected 1 argument"},
            {"-m 0", "argument -m/--multithread: invalid choice: '0'"},
            {"-m 128", "argument -m/--multithread: invalid choice: '128'"},
            {"-m N", "argument -m/--multithread: could not convert 'N' to Integer"},
            {"-c ipv4", "outfile is required"},
            {"-i x:y:z:/x-file -o 1.2.3.4/y-file", "cannot find file"},
            {"-i " + basePath + "/pcaps/magiconly.pcap -o " + newFile, "unsupported file format"},
            {"-i " + basePath + "/pcaps/1dnsidentical.pcap -o " + newFile, ""}
        };
    }

    @Test
    public void test() throws IOException {
        final String[] args = _args.split(" ");
        CLTool.main(args);
        assertThat(_err.getLog(), containsString(_output));
    }
}
