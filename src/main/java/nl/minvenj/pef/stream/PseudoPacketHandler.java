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

import org.jnetpcap.packet.PcapPacket;

/** Interface for a packet handler.
 *
 * @author Netherlands Forensic Institute.
 */
interface PseudoPacketHandler {
    /**
     * Handles the packet.
     *
     * @param packet the captured PcapPacket
     */
    void handle(PcapPacket packet);

    /**
     * Close the destination if needed.
     */
    void close();
}
