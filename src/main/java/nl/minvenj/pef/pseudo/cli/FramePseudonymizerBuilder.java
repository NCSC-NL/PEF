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

import java.io.IOException;
import java.security.InvalidKeyException;

import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.constraint.Constraints;
import nl.minvenj.pef.serialize.transform.checksum.IPv4ChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv4ICMPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv4UDPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv6UDPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.pseudonymize.IPv4AddressPseudonymizer;
import nl.minvenj.pef.serialize.transform.pseudonymize.IPv6AddressPseudonymizer;

/**
 * A builder for a FramePseudonymizer.
 *
 * A FramePseudonymizer uses a serializer to transform and serialize the frames in a certain way.
 * The settings for the serializer get set by this builder, which then constructs
 * the pseudonymizer and passes it the initialized serializer.
 *
 * @author Netherlands Forensic Institute.
 */
public class FramePseudonymizerBuilder {

    private final Processor _pseudonymizer;

    /**
     * Create a new FramePseudonymizer builder.
     */
    public FramePseudonymizerBuilder() {
        _pseudonymizer = new Processor();
    }

    /**
     * Pseudonymize IPv4 addresses.
     *
     * Uses Format Preserving Encryption, with a certain key. The mask
     * determines the bits which will be encrypted.
     *
     * The mask must be in range [0, 24]
     *
     * @param key the key to use for encryption
     * @param mask the mask determining the bits to encrypt
     * @return this
     * @throws IOException whenever I/O errors occur
     * @throws InvalidKeyException when given key is invalid
     */
    public FramePseudonymizerBuilder pseudoIPv4(final String key, final int mask) throws IOException, InvalidKeyException {
        final IPv4AddressPseudonymizer ipv4Pseudonymizer = new IPv4AddressPseudonymizer(key, mask);
        _pseudonymizer
            .addTransformer(Constraints.IPV4_UDP_DNS, "ipsource", ipv4Pseudonymizer)
            .addTransformer(Constraints.IPV4_UDP_DNS, "ipdestination", ipv4Pseudonymizer);
        return this;
    }

    /**
     * Pseudonymize IPv6 addresses.
     *
     * Uses Format Preserving Encryption, with a certain key. The mask
     * determines the bits which will be encrypted.
     *
     * The mask must be in range [0, 120]
     *
     * @param key the key to use for encryption
     * @param mask the mask determining the bits to encrypt
     * @return this
     * @throws IOException whenever I/O errors occur
     * @throws InvalidKeyException when given key is invalid
     */
    public FramePseudonymizerBuilder pseudoIPv6(final String key, final int mask) throws IOException, InvalidKeyException {
        final IPv6AddressPseudonymizer ipv6Pseudonymizer = new IPv6AddressPseudonymizer(key, mask);
        _pseudonymizer
            .addTransformer(Constraints.IPV6_UDP_DNS, "sourceaddress", ipv6Pseudonymizer)
            .addTransformer(Constraints.IPV6_UDP_DNS, "destinationaddress", ipv6Pseudonymizer);
        return this;
    }

    /**
     * Recalculate the IPv4 header checksum.
     *
     * @return this
     */
    public FramePseudonymizerBuilder calcIPv4Checksum() {
        final IPv4ChecksumCalculator ipv4ChecksumCalc = new IPv4ChecksumCalculator();
        _pseudonymizer.addTransformer(Constraints.IPV4_UDP_DNS, "headerchecksum", ipv4ChecksumCalc);
        return this;
    }

    /**
     * Recalculate the UDP checksum.
     *
     * @return this
     */
    public FramePseudonymizerBuilder calcUDPChecksum() {
        final IPv4UDPChecksumCalculator ipv4UdpChecksumCalc = new IPv4UDPChecksumCalculator();
        final IPv6UDPChecksumCalculator ipv6UdpChecksumCalc = new IPv6UDPChecksumCalculator();
        _pseudonymizer
            .addTransformer(Constraints.IPV4_UDP_DNS, "udpchecksum", ipv4UdpChecksumCalc)
            .addTransformer(Constraints.IPV6_UDP_DNS, "udpchecksum", ipv6UdpChecksumCalc);
        return this;
    }

    /**
     * Recalculate the ICMP checksum.
     *
     * @return this
     */
    public FramePseudonymizerBuilder calcICMPChecksum() {
        final IPv4ICMPChecksumCalculator ipv4IcmpChecksumCalc = new IPv4ICMPChecksumCalculator();
        _pseudonymizer.addTransformer(Constraints.ICMP_DNS, "icmpchecksum", ipv4IcmpChecksumCalc);
        return this;
    }

    /**
     * Create a new FramePseudonymizer with a serializer, initialized based on the builders settings.
     *
     * @return a new frame pseudonymizer
     */
    public FramePseudonymizer build() {
        return new FramePseudonymizer(_pseudonymizer);
    }
}
