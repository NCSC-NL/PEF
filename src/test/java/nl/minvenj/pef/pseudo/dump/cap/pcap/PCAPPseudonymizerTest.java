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
package nl.minvenj.pef.pseudo.dump.cap.pcap;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.File;
import java.io.IOException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import nl.minvenj.pef.Settings;
import nl.minvenj.pef.pseudo.FramePseudonymizer;

@RunWith(PowerMockRunner.class)
@PrepareForTest({FramePseudonymizer.class})
public class PCAPPseudonymizerTest {

    private final String _basePath = Settings.getTestBasePath();

    private final PCAPPseudonymizer _pseudonymizer = new SingleThreadedPCAPPseudonymizer(mock(FramePseudonymizer.class));

    @Test
    public void testSupportsFile() throws IOException {
        assertTrue(_pseudonymizer.supportsFile(new File(_basePath + "/pcaps", "1udpdns.pcap")));
    }

    @Test
    public void testDoesntSupportFile() throws IOException {
        assertFalse(_pseudonymizer.supportsFile(new File(_basePath + "/pcapngs", "1udpdns.pcapng")));
    }
}
