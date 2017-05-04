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
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import static nl.minvenj.pef.util.Util.tokens;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import io.parsingdata.metal.data.Environment;
import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.data.ParseValue;
import nl.minvenj.pef.Data;
import nl.minvenj.pef.metal.packet.internet.IPv6;
import nl.minvenj.pef.metal.packet.link.Ethernet2Frame;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.constraint.TransformConstraint;
import nl.minvenj.pef.serialize.process.CopyTokenSerializer;
import nl.minvenj.pef.serialize.transform.pseudonymize.IPv6AddressPseudonymizer;
import nl.minvenj.pef.util.Util;

public class IPv6PseudoTransformerTest {

    @Test
    public void testPseudoIPv6UDPDNS() throws IOException, DecoderException, InvalidKeyException {
        test(new IPv6AddressPseudonymizer("78313538767674383974646378326734", 64));
    }

    @Test
    public void testPseudoIPv6UDPDNSMocked() throws IOException, DecoderException {
        test(mockPseudo());
    }

    public void test(final IPv6AddressPseudonymizer ipv6AddressPseudonymizer) throws IOException, DecoderException {
        final byte[] bytes = Data.IPV6_UDP_MDNS;
        final ParseResult originalResult = Util.parse(bytes, Ethernet2Frame.FORMAT);
        assertTrue(originalResult.succeeded);

        final TransformConstraint constraint = new TransformConstraint(IPv6.FORMAT);
        final CopyTokenSerializer outSerializer = new CopyTokenSerializer(bytes.length);

        new Processor()
            .addTransformer(constraint, "sourceaddress", ipv6AddressPseudonymizer)
            .addTransformer(constraint, "destinationaddress", ipv6AddressPseudonymizer)
            .transformAndProcess(originalResult, outSerializer);

        final byte[] newBytes = outSerializer.outputData();
        final ParseResult newResult = Util.parse(newBytes, Ethernet2Frame.FORMAT);
        assertTrue(newResult.succeeded);

        final ParseGraph originalValues = originalResult.environment.order;
        final ParseGraph newValues = newResult.environment.order;

        assertThat(originalValues.get("sourceaddress").getValue(), is(equalTo(Hex.decodeHex("fe800000000000001cff02448da631d6".toCharArray()))));
        assertThat(originalValues.get("destinationaddress").getValue(), is(equalTo(Hex.decodeHex("ff0200000000000000000000000000fb".toCharArray()))));

        assertThat(newValues.get("sourceaddress").getValue(), is(equalTo(Hex.decodeHex("fe80000000000000b6de673148cda5be".toCharArray()))));
        assertThat(newValues.get("destinationaddress").getValue(), is(equalTo(Hex.decodeHex("ff02000000000000f00dda65997efb75".toCharArray()))));
    }

    private IPv6AddressPseudonymizer mockPseudo() {
        final IPv6AddressPseudonymizer ipv6AddressPseudonymizer = mock(IPv6AddressPseudonymizer.class);
        when(ipv6AddressPseudonymizer.context()).thenReturn(tokens(ParseGraph.NONE));
        when(ipv6AddressPseudonymizer.transform(any(ParseValue.class), any(Environment.class))).then(new Answer<ParseValue>() {

            @Override
            public ParseValue answer(final InvocationOnMock invocation) throws Throwable {
                final ParseValue value = ((ParseValue) invocation.getArguments()[0]);
                if (Arrays.equals(value.getValue(), Hex.decodeHex("fe800000000000001cff02448da631d6".toCharArray()))) {
                    return new ParseValue(value.name, value.getDefinition(), value.getOffset(), Hex.decodeHex("fe80000000000000b6de673148cda5be".toCharArray()), value.enc);
                }
                return new ParseValue(value.name, value.getDefinition(), value.getOffset(), Hex.decodeHex("ff02000000000000f00dda65997efb75".toCharArray()), value.enc);
            }
        });
        return ipv6AddressPseudonymizer;
    }
}
