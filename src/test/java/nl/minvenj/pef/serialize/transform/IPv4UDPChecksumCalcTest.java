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

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import io.parsingdata.metal.data.ParseGraph;
import io.parsingdata.metal.data.ParseResult;
import nl.minvenj.pef.Data;
import nl.minvenj.pef.metal.packet.internet.IPv4;
import nl.minvenj.pef.metal.packet.link.Ethernet2Frame;
import nl.minvenj.pef.metal.packet.transport.UDP;
import nl.minvenj.pef.serialize.Processor;
import nl.minvenj.pef.serialize.constraint.TransformConstraint;
import nl.minvenj.pef.serialize.process.CopyTokenSerializer;
import nl.minvenj.pef.serialize.transform.checksum.IPv4UDPChecksumCalculator;
import nl.minvenj.pef.util.Util;

@RunWith(Parameterized.class)
public class IPv4UDPChecksumCalcTest {

    @Parameter(0)
    public byte[] _packetBytes;

    @Parameter(1)
    public byte[] _checksum;

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            { Data.IPV4_UDP_NAT_PMP_NULL_UDP_CHECKSUM, new byte[] { (byte) 0xfe, 0x1c } }
        });
    }

    @Test
    public void testIPv4UDP() throws IOException, DecoderException {
        final byte[] bytes = _packetBytes;
        final ParseResult originalResult = Util.parse(bytes, Ethernet2Frame.FORMAT);

        final CopyTokenSerializer outSerializer = new CopyTokenSerializer(bytes.length);
        new Processor()
            .addTransformer(new TransformConstraint(IPv4.FORMAT, UDP.FORMAT), "udpchecksum", new IPv4UDPChecksumCalculator())
            .transformAndProcess(originalResult, outSerializer);

        final byte[] newBytes = outSerializer.outputData();
        final ParseResult newResult = Util.parse(newBytes, Ethernet2Frame.FORMAT);

        final ParseGraph originalValues = originalResult.environment.order;
        final ParseGraph newValues = newResult.environment.order;

        assertThat(originalValues.get("udpchecksum").getValue(), is(equalTo(new byte[]{0x00, (byte) 0x00})));
        assertThat(newValues.get("udpchecksum").getValue(), is(equalTo(_checksum)));
    }
}
