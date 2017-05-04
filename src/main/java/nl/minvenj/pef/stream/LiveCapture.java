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
package nl.minvenj.pef.stream;

import static nl.minvenj.pef.serialize.transform.ParseValueTransformerFactory.TransformerId;
import static nl.minvenj.pef.serialize.transform.ParseValueTransformerFactory.getParseValueTransformer;
import static nl.minvenj.pef.serialize.transform.ParseValueTransformerFactory.testParseValueTransformerConfiguration;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import org.apache.commons.configuration2.HierarchicalConfiguration;
import org.apache.commons.configuration2.XMLConfiguration;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.configuration2.ex.ConversionException;
import org.apache.commons.configuration2.tree.ImmutableNode;

import nl.minvenj.pef.exception.PEFException;
import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.pseudo.dump.cap.pcap.SingleThreadedPCAPPseudonymizer;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.constraint.Constraints;
import nl.minvenj.pef.serialize.transform.ParseValueTransformerFactory;
import nl.minvenj.pef.serialize.transform.checksum.IPv4ChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv4UDPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv6UDPChecksumCalculator;
import nl.minvenj.pef.util.AlgorithmParameter;

/**
 * LiveCapture class
 * With this class the tool to start a packet sniffer can be initialized.
 *
 * @author Netherlands Forensic Institute.
 */
public class LiveCapture {
    private static FileHandler logFileHandler = null;
    static private final Logger logger = Logger.getLogger("");

    /**
     * Initializes a logger.
     *
     * @param logPath The location and name of the log file
     * @throws SecurityException on opening the log file
     * @throws IOException on opening the log file
     */
    private static void initLogger(final String logPath) throws SecurityException, IOException, IllegalArgumentException {
        logFileHandler = new FileHandler(logPath, true);
        Logger initLogger = Logger.getLogger("");
        logFileHandler.setFormatter(new SimpleFormatter());
        initLogger.addHandler(logFileHandler);
        initLogger.setLevel(Level.CONFIG);
    }

    private static void testPseudonymizationSettings(final XMLConfiguration config) throws ConfigurationException, IllegalArgumentException, ClassNotFoundException {
        List<HierarchicalConfiguration<ImmutableNode>> fields = config.configurationsAt("fields.field");
        for (HierarchicalConfiguration field : fields) {
            // Test the name of the field.
            final String constraint = field.getString("constraint");
            final String fieldName = field.getString("name");
            final String algorithmName = field.getString("algorithm.name");
            if ( (fieldName == null) || (constraint == null) || (algorithmName == null) )
                throw new NoSuchElementException("Name of the field, constraint and algoritm needs to be set for each field.");
            // Test the constraint.
            if (!Constraints.CONSTRAINT_MAP.containsKey(field.getString("constraint"))) {
                throw new ConfigurationException(field.getString("constraint") + "should be defined in constraints list (Constraints.java)");
            }
            // TODO PEF-78: Test if the fieldName matches with the context.
            // TODO PEF-79: No expression support.
            // Test if the algorithm is part of the configured algorithms.
            List<HierarchicalConfiguration> parameters = field.childConfigurationsAt("algorithm.params");
            List<AlgorithmParameter> parameterList = new ArrayList<>();

            //TODO PEF-81: Create here a specific parameter type.
            for (HierarchicalConfiguration parameter : parameters) {
                parameterList.add(new AlgorithmParameter(parameter.getString("name"), parameter.getString("value"), Class.forName(parameter.getString("type"))));
            }
            final StringBuilder buffer = new StringBuilder();
            if (!testParseValueTransformerConfiguration(TransformerId.valueOf(algorithmName), parameterList, buffer)) {
                throw new ConfigurationException("Error in configuration for algorithm "+ algorithmName + " " + buffer.toString());
            }
        }
    }

    private static boolean checkConfiguration(final XMLConfiguration config) {
        final long MAX_FILE_SIZE = 1000;
        //Test if all fields are available. For now it exits per field.
        try {
            //First all normal fields. The library field is optional, default to metal.
            final boolean live = config.getBoolean("live");
            final String inputFile = config.getString("input");
            if (!live) {
                if (inputFile == null) {
                    throw new NoSuchElementException("For offline use, the parameter 'input' file needs to be specified");
                }
                File testInput = new File(inputFile);
                if (!testInput.exists()) {
                    logger.severe("The specified input file " + testInput.toPath().toAbsolutePath().toString() + " does not exist.");
                    return false;
                }
                if (!testInput.canRead()) {
                    logger.severe("The user is not allowed to read the file");
                }
            }
            // Will throw an error if conversion fails.
            config.getBoolean("remove_failing_packets");
            config.getBoolean("remove_unknown_protocols");
            config.getBoolean("checksum_reset");
            config.getBoolean("timer", false);
            final String outputDir = config.getString("output_directory");
            // The file size does not need to be specified. Therefore a default is provided.
            final long fileSize = config.getLong("file_size", 120);
            if (fileSize > MAX_FILE_SIZE) {
                logger.severe(" A file size over 1000 MB is not supported.");
                return false;
            }
            if (outputDir == null) {
                throw new NoSuchElementException("The output_directory parameter is not set");
            }
            final Path path = Paths.get(outputDir);
            if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                logger.severe("The output directory configured is not a path.");
                return false;
            }
            if (!Files.isWritable(path)) {
                logger.severe("The selected output directory is not writable.");
                return false;
            }
            final String parseLibrary = config.getString("parse_library");
            if (! parseLibrary.equals("metal")) {
                logger.severe("Only the metal library is currently implemented as parse library.");
                return false;
            }
            String [] packetInputLibraryOptions = {"metal","jnetpcap"};
            final String packetInputLibrary = config.getString("packets_input_library");
            if (!Arrays.asList(packetInputLibraryOptions).contains(packetInputLibrary)) {
                logger.severe("Packet Input Library: "+ packetInputLibrary + " is not implemented.");
            }
            // Test all algorithms and their parameters.
            testPseudonymizationSettings(config);
        }
        catch (NoSuchElementException e) {
            logger.severe("Input element is missing: "+ e.getMessage());
            return false;
        }
        catch (InvalidPathException e) {
            logger.severe("The path specified in the config file is invalid: " + e.getMessage());
            return false;
        }
        catch (ConversionException e) {
            logger.severe("Conversion failed: " + e.getMessage());
            return false;
        }
        catch (ClassNotFoundException e) {
            logger.severe("Error in creating a parameter: the class could not be found: "+ e.getMessage());
            return false;
        }
        catch (ConfigurationException e) {
            logger.severe(e.getMessage());
            return false;
        }
        return true;
    }

    private static FramePseudonymizer initMetalPseudonymizerWith(final XMLConfiguration config) throws InvalidKeyException, ClassNotFoundException {
        Processor processor = new Processor();

        List<HierarchicalConfiguration<ImmutableNode>> fields = config.configurationsAt("fields.field");

        for (HierarchicalConfiguration field : fields) {
            List<HierarchicalConfiguration> parameters = field.childConfigurationsAt("algorithm.params");
            List<AlgorithmParameter> parameterList = new ArrayList<>();
            for (HierarchicalConfiguration parameter : parameters) {
                parameterList.add(new AlgorithmParameter(parameter.getString("name"), parameter.getString("value"), Class.forName(parameter.getString("type"))));
            }
            // Add the transformers
            processor.addTransformer(Constraints.CONSTRAINT_MAP.get(field.getString("constraint")), field.getString("name"),
                    getParseValueTransformer(ParseValueTransformerFactory.TransformerId.valueOf(field.getString("algorithm.name")), parameterList));
            logger.info("Packets containing " + field.getString("name") +  " will be pseudonymized based on this constraint: " + field.getString("constraint")
                    + ", with this algorithm "+ field.getString("algorithm.name") );
        }
        // TODO PEF-43:  Move and change functionality.
        if (config.getBoolean("checksum_reset")) {
            processor.addTransformer(Constraints.IPV4_UDP_DNS, "udpchecksum",new IPv4UDPChecksumCalculator())
                    .addTransformer(Constraints.IPV6_UDP_DNS, "udpchecksum", new IPv6UDPChecksumCalculator())
                    .addTransformer(Constraints.IPV4_UDP_DNS, "headerchecksum", new IPv4ChecksumCalculator())
                    .addTransformer(Constraints.ICMP_DNS, "icmpchecksum", new IPv6UDPChecksumCalculator());
        }
        return new FramePseudonymizer(processor);
    }

    private static void runPEF (XMLConfiguration config) {
        // Parse the configuration and call the correct entries for starting the tool.
        final String parseLibrary = config.getString("parse_library");
        final String packetsInputLibrary = config.getString("packets_input_library");
        boolean live = config.getBoolean("live");
        boolean timer = config.getBoolean("timer", false);

        final String destination = Paths.get(config.getString("output_directory")).toAbsolutePath().toString() + File.separator +  config.getString("output_file");
        final String input = config.getString("input", "");

        try {
            final FramePseudonymizer pseudonymizer = initMetalPseudonymizerWith(config);
            if (packetsInputLibrary.equals("metal")) {
                assert(!live); // This configuration option does not exists and should have been checked before!
                logger.info(packetsInputLibrary + "is used as input library.");
                new SingleThreadedPCAPPseudonymizer(pseudonymizer).pseudonymize(new File(input),new File(destination));
            }
            // Only jnetpcap is furthermore supported for now
            else if (packetsInputLibrary.equals("jnetpcap")) {
                logger.info(packetsInputLibrary + " is used as packets input library.");
                // As input the device can be configured. If empty, the default device is used.
                final PcapSniffer sniffer = new PcapSniffer(input);
                //Set the handler and pseudonymize.
                if (live && (config.get(long.class, "file_size")!= null) ) {
                    sniffer.setFileSize(config.getLong("file_size"));
                }
                logger.info("Output will be stored in "+ destination);
                sniffer.handleWithMetal(live, timer, destination, pseudonymizer);
            }
            else {
                logger.info(packetsInputLibrary + " as input library is not supported.");
            }
        }
        catch (IOException e) {
            throw new PEFException("There are problems with the input or output capture file: "+ e.getMessage());
        }
        catch (ConversionException e) {
            throw new PEFException("Conversion of configured value failed: "+ e.getMessage());
        }
        catch (InvalidKeyException e) {
            throw new PEFException("An invalid key is configured: "+ e.getMessage());
        }
        catch (ClassNotFoundException e) {
            throw new PEFException("The class type could not be found for the parameter: "+ e.getMessage());
        }
    }

    /**
     * Main function to start the tool for pseudonymization of packets.
     *
     * @param args command line tool arguments
     */
    public static void main(String[] args) {
        String xmlConfigFile;
        if (args.length == 1) {
            xmlConfigFile = args[0];
        }
        else {
            xmlConfigFile = "configuration.xml";
        }
        // Test if the file exists.
        File configFile = new File(xmlConfigFile);
        if (!configFile.exists()) {
            System.out.println("Create the file configuration.xml with the settings for pseudonymization. " +
                    "You can copy the configuration.proto.xml file as template.");
            // Exit the application.
            return;
        }
        else {
            System.out.println("Using " + xmlConfigFile + " as configuration file.");
        }
        Parameters params = new Parameters();
        FileBasedConfigurationBuilder<XMLConfiguration> builder = new FileBasedConfigurationBuilder<>(XMLConfiguration.class)
                .configure(params.xml()
                        .setFileName(xmlConfigFile));
        try {
            XMLConfiguration config = builder.getConfiguration();
            // Check the configuration.
            String logFile = config.getString("log_file", "default_log.txt");
            initLogger(logFile);
            if (checkConfiguration(config)) {
                runPEF(config);
            }
        }
        catch(ConfigurationException cex) {
            // Loading of the configuration file failed
            cex.printStackTrace();
        }
        catch (IOException | SecurityException | IllegalArgumentException e) {
            // The logger could not be initialized.
            System.err.println("The logger could not be initialized " + e.getMessage());
        }
        catch (PEFException e) {
            System.err.println(e.getMessage());
        }
    }
}