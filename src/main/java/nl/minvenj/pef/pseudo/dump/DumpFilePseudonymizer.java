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
package nl.minvenj.pef.pseudo.dump;

import java.io.File;
import java.io.IOException;

/**
 *  for a network dump file.
 *
 * A DumpFilePseudonymizer can read a certain dump file format which contains captured
 * packet information from a network stream. The pseudonymizer can then transform information
 * (pseudonymize), and write this data back to an output file.
 *
 * Examples of dump file formats are PCAP, PCAPNG.
 *
 * @author Netherlands Forensic Institute.
 */
public interface DumpFilePseudonymizer {

    /**
     * Returns true if the file format is recognised and supported by the pseudonymizer.
     *
     * @param file the file to check
     *
     * @return true if it is supported, else false
     * @throws IOException when an I/O error occurs during reading/parsing
     */
    boolean supportsFile(File file) throws IOException;

    /**
     * Pseudonymize packets in a given file and writes to the new file reflecting the changes.
     *
     * Calling this method assumes that supportsFile(inFile) returns true. If not,
     * this method will break.
     *
     * @param inFile the input file to perform the pseudonymization with
     * @param outFile the output file to create/overwrite and write the data to
     *
     * @return the created, pseudonymized file
     * @throws IOException whenever I/O errors occur
     */
    File pseudonymize(final File inFile, final File outFile) throws IOException;
}
