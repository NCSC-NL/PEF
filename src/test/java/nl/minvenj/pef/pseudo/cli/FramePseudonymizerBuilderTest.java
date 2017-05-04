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

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.verifyNew;
import static org.powermock.api.mockito.PowerMockito.whenNew;

import java.io.IOException;
import java.security.InvalidKeyException;

import nl.minvenj.pef.serialize.Processor;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.serialize.constraint.Constraints;
import nl.minvenj.pef.serialize.constraint.TransformConstraint;
import nl.minvenj.pef.serialize.transform.ParseValueTransformer;
import nl.minvenj.pef.serialize.transform.checksum.IPv4ChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv4UDPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.checksum.IPv6UDPChecksumCalculator;
import nl.minvenj.pef.serialize.transform.pseudonymize.IPv4AddressPseudonymizer;
import nl.minvenj.pef.serialize.transform.pseudonymize.IPv6AddressPseudonymizer;

// JaCoCo doesn't play nice with PowerMock, so we won't get any coverage
// Hours wasted to fix coverage reporting: 1.
@RunWith(PowerMockRunner.class)
@PrepareForTest({FramePseudonymizerBuilder.class, Processor.class, FramePseudonymizer.class})
public class FramePseudonymizerBuilderTest {

    @Mock
    Processor _pseudonymizer;

    @Mock
    FramePseudonymizer _framePseudonymizer;

    @Mock
    IPv4AddressPseudonymizer _iPv4AddressPseudonymizer;

    @Mock
    IPv6AddressPseudonymizer _iPv6AddressPseudonymizer;

    @Mock
    IPv4ChecksumCalculator _iPv4ChecksumCalculator;

    @Mock
    IPv4UDPChecksumCalculator _iPv4UDPChecksumCalculator;

    @Mock
    IPv6UDPChecksumCalculator _iPv6UDPChecksumCalculator;

    @Before
    public void setUp() throws Exception {
        // black magic constructor mocking:
        whenNew(Processor.class).withAnyArguments().thenReturn(_pseudonymizer);
        whenNew(FramePseudonymizer.class).withAnyArguments().thenReturn(_framePseudonymizer);

        whenNew(IPv4AddressPseudonymizer.class).withAnyArguments().thenReturn(_iPv4AddressPseudonymizer);
        whenNew(IPv6AddressPseudonymizer.class).withAnyArguments().thenReturn(_iPv6AddressPseudonymizer);
        whenNew(IPv4ChecksumCalculator.class).withAnyArguments().thenReturn(_iPv4ChecksumCalculator);
        whenNew(IPv4UDPChecksumCalculator.class).withAnyArguments().thenReturn(_iPv4UDPChecksumCalculator);
        whenNew(IPv6UDPChecksumCalculator.class).withAnyArguments().thenReturn(_iPv6UDPChecksumCalculator);

        when(_pseudonymizer.addTransformer(any(TransformConstraint.class), anyString(), any(ParseValueTransformer.class))).thenReturn(_pseudonymizer);
    }

    @Test
    public void testPseudoIPv4() throws IOException, InvalidKeyException {
        new FramePseudonymizerBuilder().pseudoIPv4("foo", 42);

        verify(_pseudonymizer).addTransformer(Constraints.IPV4_UDP_DNS, "ipsource", _iPv4AddressPseudonymizer);
        verify(_pseudonymizer).addTransformer(Constraints.IPV4_UDP_DNS, "ipdestination", _iPv4AddressPseudonymizer);

        verifyNoMoreInteractions(_pseudonymizer);
    }

    @Test
    public void testPseudoIPv6() throws IOException, InvalidKeyException {
        new FramePseudonymizerBuilder().pseudoIPv6("bar", 43);

        verify(_pseudonymizer).addTransformer(Constraints.IPV6_UDP_DNS, "sourceaddress", _iPv6AddressPseudonymizer);
        verify(_pseudonymizer).addTransformer(Constraints.IPV6_UDP_DNS, "destinationaddress", _iPv6AddressPseudonymizer);

        verifyNoMoreInteractions(_pseudonymizer);
    }

    @Test
    public void testCalcIPv4Checksum() {
        new FramePseudonymizerBuilder().calcIPv4Checksum();

        verify(_pseudonymizer).addTransformer(Constraints.IPV4_UDP_DNS, "headerchecksum", _iPv4ChecksumCalculator);

        verifyNoMoreInteractions(_pseudonymizer);
    }

    @Test
    public void testCalcUDPChecksum() {
        new FramePseudonymizerBuilder().calcUDPChecksum();

        verify(_pseudonymizer).addTransformer(Constraints.IPV4_UDP_DNS, "udpchecksum", _iPv4UDPChecksumCalculator);
        verify(_pseudonymizer).addTransformer(Constraints.IPV6_UDP_DNS, "udpchecksum", _iPv6UDPChecksumCalculator);

        verifyNoMoreInteractions(_pseudonymizer);
    }

    @Test
    public void testBuild() throws Exception {
        new FramePseudonymizerBuilder().build();

        verifyNew(FramePseudonymizer.class).withArguments(_pseudonymizer);
    }
}
