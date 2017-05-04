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

import java.security.InvalidKeyException;
import java.util.List;

import nl.minvenj.pef.serialize.transform.checksum.IPv4ChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv4ICMPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv4TCPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv4UDPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv6TCPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv6UDPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.pseudonymize.IPv4AddressPseudonymizer;
import nl.minvenj.pef.serialize.transform.pseudonymize.IPv6AddressPseudonymizer;
import nl.minvenj.pef.util.AlgorithmParameter;
import nl.minvenj.pef.util.Util;

/**
 * ParseValueTransformer Factory
 *
 * Factory for the creation of the ParseValueTransformers that are configured.
 * When creating a new transformer that you want to add, you have to update the functions inside this file.
 * - Add a transformerId which is used as string inside the configuration file.
 * - Add the parameter checks to the testParseValueTransformerConfiguration function.
 * - Add the id to the switch and cast the parameters correctly
 *
 * @author Netherlands Forensic Institute.
 */
public class ParseValueTransformerFactory {
    public enum TransformerId {
        FFX_IPV6ADDRESS,
        FFX_IPV4ADDRESS,
        IPV4_HEADERCHECKSUM,
        IPV4_ICMP_CHECKSUM,
        IPV4_UDP_CHECKSUM,
        IPV4_TCP_CHECKSUM,
        IPV6_TCP_CHECKSUM,
        IPV6_UDP_CHECKSUM
    }

    /**
     *  This static function creates the ParseValueTransformer.
     * @param transformerId the id for the transformer
     * @param parameters the parameters to configure the transformer with
     * @return the transformer instance
     * @throws InvalidKeyException
     */
    public static final ParseValueTransformer getParseValueTransformer(final TransformerId transformerId, final List<AlgorithmParameter> parameters) throws InvalidKeyException {
        switch (transformerId) {
            case FFX_IPV4ADDRESS:
                return new IPv4AddressPseudonymizer(parameters.get(0).getValue(), Integer.parseInt(parameters.get(1).getValue()));
            case FFX_IPV6ADDRESS:
                return new IPv6AddressPseudonymizer(parameters.get(0).getValue(), Integer.parseInt(parameters.get(1).getValue()));
            case IPV4_HEADERCHECKSUM:
                return new IPv4ChecksumCalculator();
            case IPV4_ICMP_CHECKSUM:
                return new IPv4ICMPChecksumCalculator();
            case IPV4_TCP_CHECKSUM:
                return new IPv4TCPChecksumCalculator();
            case IPV4_UDP_CHECKSUM:
                return new IPv4UDPChecksumCalculator();
            case IPV6_TCP_CHECKSUM:
                return new IPv6TCPChecksumCalculator();
            case IPV6_UDP_CHECKSUM:
                return new IPv6UDPChecksumCalculator();
            default:
                throw new InvalidKeyException("Transformer " + transformerId.name() + "not implemented.");
        }
    }

    /**
     * Test for the parameters per configured function. If there are no special requirements besides that a parameter type and value
     * should match you can would check the size and then each parameter with parameter.get(0).testParameter("name", classtype, message);
     * @param transformerId The {@link ParseValueTransformer} Id to be used.
     * @param parameters The input parameters to test
     * @param message The error message. If the size of the parameters is wrong the message is currently not set.
     * @return
     */
    public static boolean testParseValueTransformerConfiguration(final TransformerId transformerId, final List<AlgorithmParameter> parameters, final StringBuilder message) {
        switch (transformerId) {
            case FFX_IPV4ADDRESS:
                return (( parameters.size() == 2 ) && testIPV4AddressParameters(parameters.get(0), parameters.get(1), message) );
            case FFX_IPV6ADDRESS:
                return(( parameters.size() == 2 ) && testIPV6AddressParameters(parameters.get(0), parameters.get(1), message) );
            case IPV4_HEADERCHECKSUM:
                return (parameters.size() == 0);
            case IPV4_ICMP_CHECKSUM:
                return (parameters.size() == 0);
            case IPV4_TCP_CHECKSUM:
                return (parameters.size() == 0);
            case IPV4_UDP_CHECKSUM:
                return(parameters.size() == 0);
            case IPV6_TCP_CHECKSUM:
                return (parameters.size() == 0);
            case IPV6_UDP_CHECKSUM:
                return (parameters.size() == 0);
            default:
                message.append("Transformer " + transformerId.name() + "not implemented.");
                return false;
        }
    }

    private static boolean testIPV4AddressParameters(final AlgorithmParameter key, final AlgorithmParameter mask, final StringBuilder message) {
        boolean keyOk = key.testParameter("key", String.class, message);
        if (keyOk) {
            keyOk = ((key.getValue().length() == 32) && Util.stringNumInRadix(key.getValue(), 16));
            if (!keyOk) {
                message.append("AES key must be a 32 character hexidecimal string (128-bit)");
            }
        }
        boolean maskOk = mask.testParameter("mask", Integer.class, message);
        if(maskOk) {
            int maskInt = Integer.parseInt(mask.getValue());
            if (maskInt < 0 || maskInt > 24) {
                message.append("The mask for IPV4Address pseudonymizer should be in between 0 and 24");
                maskOk = false;
            }
        }
        return (keyOk && maskOk);
    }

    private static boolean testIPV6AddressParameters(final AlgorithmParameter key, final AlgorithmParameter mask, final StringBuilder message) {
        boolean keyOk = key.testParameter("key", String.class, message);
        if (keyOk) {
            keyOk = ((key.getValue().length() == 32) && Util.stringNumInRadix(key.getValue(), 16));
            if (!keyOk) {
                message.append("AES key must be a 32 character hexidecimal string (128-bit)");
            }
        }
        boolean maskOk = mask.testParameter("mask", Integer.class, message);
        if(maskOk) {
            int maskInt = Integer.parseInt(mask.getValue());
            if (maskInt < 0 || maskInt > 120) {
                message.append("The mask for IPV6Address pseudonymizer should be in between 0 and 120");
                maskOk = false;
            }
        }
        return (keyOk && maskOk);
    }
}
