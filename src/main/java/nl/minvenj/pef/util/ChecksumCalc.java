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
package nl.minvenj.pef.util;

import static nl.minvenj.pef.util.Util.unsignedShortToByteArray;

import java.nio.ByteOrder;

/**
 * Utility class to calculate checksums with.
 *
 * @author Netherlands Forensic Institute.
 */
public final class ChecksumCalc {

    private ChecksumCalc() {
    }

    /**
     * Internet checksum calculator. (RFC 1071)
     * The  checksum is calculated by forming the ones' complement of the ones'
     * complement sum of the header's 16-bit words. This function is also used to
     * recalculate a checksum therefore the checksum, available in the data is not always zeroed beforehand.
     *
     * @param checksumData the data over which to calculate the checksum
     * @return the calculated checksum in bytes
     */

    public static byte[] calculateInternetChecksum(final byte[] checksumData) {
        int sum = 0;
        for (int i = 0; i < checksumData.length - 1; i += 2) {
            final int firstHalf = Util.toUnsignedInt(checksumData[i]) << 8;
            final int secondHalf = Util.toUnsignedInt(checksumData[i + 1]);
            sum += firstHalf | secondHalf;
        }

        if ((checksumData.length & 1) == 1) {
            sum += Util.toUnsignedInt(checksumData[checksumData.length - 1]) << 8;
        }

        sum = carryTo16(sum);
        return unsignedShortToByteArray(~sum & 0xFFFF, ByteOrder.BIG_ENDIAN);
    }

    private static int carryTo16(final int val) {
        // Sum both 16 bit halves (both as unsigned), until the value fits 16 bits.
        int v = val;
        while ((v >>> 16) != 0) {
            v = (v >>> 16) + (v & 0xFFFF);
        }
        return v;
    }
}