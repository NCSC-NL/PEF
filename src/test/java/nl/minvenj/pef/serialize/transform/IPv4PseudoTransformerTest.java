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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import static nl.minvenj.pef.util.TestUtil.hex;
import static nl.minvenj.pef.util.TestUtil.hexStringToBytes;
import static nl.minvenj.pef.util.Util.tokens;

import java.io.IOException;
import java.security.InvalidKeyException;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.data.ParseValue;
import nl.minvenj.pef.Data;
import nl.minvenj.pef.metal.packet.internet.IPv4;
import nl.minvenj.pef.metal.packet.link.Ethernet2Frame;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.constraint.TransformConstraint;
import nl.minvenj.pef.serialize.process.CopyTokenSerializer;
import nl.minvenj.pef.serialize.transform.pseudonymize.IPv4AddressPseudonymizer;
import nl.minvenj.pef.util.Util;

public class IPv4PseudoTransformerTest {

    @Test
    public void testPseudoIPv4UDPDNS() throws IOException, DecoderException, InvalidKeyException {
        test(new IPv4AddressPseudonymizer("78313538767674383974646378326734", 16));
    }

    @Test
    public void testPseudoIPv4UDPDNSMocked() throws IOException, DecoderException {
        test(mockPseudo());
    }

    public void test(final IPv4AddressPseudonymizer ipv4AddressPseudonymizer) throws IOException, DecoderException {
        final byte[] bytes = Data.IPV4_UDP_NAT_PMP;
        final ParseResult originalResult = Util.parse(bytes, Ethernet2Frame.FORMAT);

        final TransformConstraint constraint = new TransformConstraint(IPv4.FORMAT);
        final CopyTokenSerializer outSerializer = new CopyTokenSerializer(bytes.length);

        new Processor()
            .addTransformer(constraint, "ipsource", ipv4AddressPseudonymizer)
            .addTransformer(constraint, "ipdestination", ipv4AddressPseudonymizer)
            .transformAndProcess(originalResult, outSerializer);

        final byte[] newBytes = outSerializer.outputData();
        final ParseResult newResult = Util.parse(newBytes, Ethernet2Frame.FORMAT);

        final ParseGraph originalValues = originalResult.environment.order;
        final ParseGraph newValues = newResult.environment.order;

        assertThat(hex(originalValues.get("ipsource").getValue()), is(equalTo("AC10FF01")));
        assertThat(hex(originalValues.get("ipdestination").getValue()), is("AC100001"));

        assertThat(hex(newValues.get("ipsource").getValue()), is(equalTo("AC101C42")));
        assertThat(hex(newValues.get("ipdestination").getValue()), is(equalTo("AC1002B3")));
    }

    private IPv4AddressPseudonymizer mockPseudo() {
        final IPv4AddressPseudonymizer ipv4AddressPseudonymizer = mock(IPv4AddressPseudonymizer.class);
        when(ipv4AddressPseudonymizer.context()).thenReturn(tokens(ParseGraph.NONE));
        when(ipv4AddressPseudonymizer.transform(any(ParseValue.class), any(Environment.class))).then(new Answer<ParseValue>() {

            @Override
            public ParseValue answer(final InvocationOnMock invocation) throws Throwable {
                final ParseValue value = ((ParseValue) invocation.getArguments()[0]);
                if (hex(value.getValue()).equals("AC10FF01")) {
                    return new ParseValue(value.name, value.getDefinition(), value.getOffset(), hexStringToBytes("AC101C42"), value.enc);
                }
                return new ParseValue(value.name, value.getDefinition(), value.getOffset(), hexStringToBytes("AC1002B3"), value.enc);
            }
        });
        return ipv4AddressPseudonymizer;
    }
}
