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

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.List;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentGroup;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.internal.HelpScreenException;
import nl.minvenj.pef.exception.UnsupportedFileFormatException;
import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.pseudo.cli.action.ChecksumCheckAction;
import nl.minvenj.pef.pseudo.cli.action.FileCheckAction;
import nl.minvenj.pef.pseudo.cli.action.Pseudo4CheckAction;
import nl.minvenj.pef.pseudo.cli.action.Pseudo6CheckAction;
import nl.minvenj.pef.pseudo.dump.DumpFilePseudonymizer;
import nl.minvenj.pef.pseudo.dump.cap.pcap.MultiThreadedPCAPPseudonymizer;
import nl.minvenj.pef.pseudo.dump.cap.pcap.SingleThreadedPCAPPseudonymizer;
import nl.minvenj.pef.pseudo.dump.cap.pcapng.MultiThreadedPCAPNGPseudonymizer;
import nl.minvenj.pef.pseudo.dump.cap.pcapng.SingleThreadedPCAPNGPseudonymizer;

/**
 * A command line tool used to pseudonymize certain DNS packets inside a PCAP/PCAPNG file.
 *
 * It does this by scanning the structures inside the dump file, searching and extracting
 * the packet data contained inside these structures, and then applying transformations
 * on these packets based on the settings passed to the tool. Afterwards the data
 * is written back to a new file.
 *
 * Run with -h for help.
 *
 * @author Netherlands Forensic Institute.
 */
public final class CLTool {

    private CLTool() {
    }

    public static void main(final String[] args) {
        final ArgumentParser parser = ArgumentParsers.newArgumentParser(CLTool.class.getSimpleName())
            .description("Tool to pseudonymize certain DNS packets packets in PCAP or PCAPNG files.")
            .version("0.0.1");

        final ArgumentGroup requiredGroup = parser.addArgumentGroup("required arguments");

        requiredGroup.addArgument("-i", "--infile")
            .required(true)
            .metavar("infile")
            .type(String.class)
            .action(new FileCheckAction())
            .help("the input file to process (either PCAP or PCAPNG)");
        requiredGroup.addArgument("-o", "--outfile")
            .required(true)
            .metavar("outfile")
            .type(String.class)
            .help("the output file to create and write to");
        parser.addArgument("-v", "--version")
            .action(Arguments.version())
            .help("show the program version");
        parser.addArgument("-4", "--pseudo4")
            .nargs(2)
            .metavar("key", "mask")
            .action(new Pseudo4CheckAction())
            .help("pseudonymize the masked part of IPv4 addresses using FPE, with given key");
        parser.addArgument("-6", "--pseudo6")
            .nargs(2)
            .metavar("key", "mask")
            .action(new Pseudo6CheckAction())
            .help("pseudonymize the masked part of IPv6 addresses using FPE, with given key");
        parser.addArgument("-c", "--checksum")
            .nargs(1)
            .metavar("[ipv4,udp,icmp] or all")
            .action(new ChecksumCheckAction())
            .help("recalculate checksums of given protocols (given as comma separated list or 'all')");
        parser.addArgument("-m", "--multithread")
            .metavar("numthreads")
            .type(Integer.class)
            .choices(Arguments.range(1, 127)) // TODO: range as [1, maxDetectedCores]?
            .help("use multithreading with specified number of threads, in range of [1, 127]");

        try {
            final Namespace cmdResult = parser.parseArgs(args);
            runTool(cmdResult);
        }
        catch (final HelpScreenException hse) {
            // this is the normal behaviour, throwing exception when asking for help
            // in this case, do nothing
        }
        catch (final ArgumentParserException ape) {
            System.err.println(parser.formatUsage() + CLTool.class.getSimpleName() + ": error: " + ape.getMessage());
        }
    }

    private static void runTool(final Namespace cmdResult) {
        try {
            final File inFile = new File(cmdResult.getString("infile"));
            final File outFile = new File(cmdResult.getString("outfile"));

            runToolOnfiles(cmdResult, inFile, outFile);
        }
        // TODO PEF-61 add logging
        catch (final UnsupportedFileFormatException uffe) {
            System.err.println(uffe.getMessage());
        }
        catch (final InvalidKeyException ike) {
            System.err.println("key should be a 16-byte hexadecimal number (128-bit)");
        }
        catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    private static void runToolOnfiles(final Namespace cmdResult, final File inFile, final File outFile) throws InvalidKeyException, IOException {
        final List<DumpFilePseudonymizer> pseudonymizers = new ArrayList<>();

        pseudonymizers.add(initPCAPPseudonymizer(cmdResult));
        pseudonymizers.add(initPCAPPNGseudonymizer(cmdResult));

        for (final DumpFilePseudonymizer pseudonymizer : pseudonymizers) {
            if (pseudonymizer.supportsFile(inFile)) {
                pseudonymizer.pseudonymize(inFile, outFile);
                return;
            }
        }
        throw new UnsupportedFileFormatException("unsupported file format for infile");
    }

    private static DumpFilePseudonymizer initPCAPPseudonymizer(final Namespace cmdResult) throws InvalidKeyException, IOException {
        final Integer mt = cmdResult.getInt("multithread");
        if (mt == null) {
            return new SingleThreadedPCAPPseudonymizer(initPseudonymizerWith(cmdResult));
        }
        else {
            final List<FramePseudonymizer> pseudonymizers = initMultiplePseudonymizers(cmdResult, mt);
            return new MultiThreadedPCAPPseudonymizer(pseudonymizers);
        }
    }

    private static DumpFilePseudonymizer initPCAPPNGseudonymizer(final Namespace cmdResult) throws IOException, InvalidKeyException {
        final Integer mt = cmdResult.getInt("multithread");
        if (mt == null) {
            return new SingleThreadedPCAPNGPseudonymizer(initPseudonymizerWith(cmdResult));
        }
        else {
            final List<FramePseudonymizer> pseudonymizers = initMultiplePseudonymizers(cmdResult, mt);
            return new MultiThreadedPCAPNGPseudonymizer(pseudonymizers);
        }
    }

    private static List<FramePseudonymizer> initMultiplePseudonymizers(final Namespace cmdResult, final int amount) throws IOException, InvalidKeyException {
        final List<FramePseudonymizer> pseudonymizers = new ArrayList<>();
        for (int i = 0; i < amount; i++) {
            pseudonymizers.add(initPseudonymizerWith(cmdResult));
        }
        return pseudonymizers;
    }

    private static FramePseudonymizer initPseudonymizerWith(final Namespace cmdResult) throws IOException, InvalidKeyException {
        final FramePseudonymizerBuilder builder = new FramePseudonymizerBuilder();
        if (cmdResult.get("pseudo4") != null) {
            final List<Object> params = cmdResult.getList("pseudo4");
            builder.pseudoIPv4((String) params.get(0), Integer.parseInt(params.get(1).toString().replaceAll("/", "")));
        }
        if (cmdResult.get("pseudo6") != null) {
            final List<Object> params = cmdResult.getList("pseudo6");
            builder.pseudoIPv6((String) params.get(0), Integer.parseInt(params.get(1).toString().replaceAll("/", "")));
        }
        if (cmdResult.get("checksum") != null) {
            final List<Object> params = cmdResult.getList("checksum");
            if (params.contains("all")) {
                builder.calcUDPChecksum();
                builder.calcIPv4Checksum();
                builder.calcICMPChecksum();
            }
            else {
                if (params.contains("udp")) {
                    builder.calcUDPChecksum();
                }
                if (params.contains("ipv4")) {
                    builder.calcIPv4Checksum();
                }
                if (params.contains("icmp")) {
                    builder.calcICMPChecksum();
                }
            }
        }
        return builder.build();
    }
}
