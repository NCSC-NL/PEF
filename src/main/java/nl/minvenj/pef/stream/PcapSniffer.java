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

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import nl.minvenj.pef.pseudo.FramePseudonymizer;

/**
 * A Pcap sniffer based on the JNetPcap library. Opens a live stream and constructs
 * a packet handler based on the input provided.
 *
 * @author Netherlands Forensic Institute.
 */
public class PcapSniffer {
    private static final Logger logger = Logger.getLogger(LiveCapture.class.getName());
    private final String _input;
    private long _maxBytes = 120000;

    /**
     * Creates a PcapSniffer. Initializes the input and ensures there is max number of bytes
     * captured for live streams. It is up to the user to decide on how to use the sniffer.
     *
     * @param input, the device or input file to be used
     */
    public PcapSniffer(final String input){
        _input = input;
    }

    //Can be a handler type
    public void setFileSize(long maxMBytes) {
        _maxBytes = maxMBytes * 1000;
    }

    public void handleWithMetal(boolean live, boolean timed, String destination, FramePseudonymizer pseudonymizer)
    {
        long startTime  = System.currentTimeMillis();
        final Pcap pcap;
        final PcapPacketHandler<PseudoPacketHandler> handler;
        try {
            if (live) {
                pcap = getLivePcapStream(_input);
                handler =  getByteLimitedHandler(pcap, _maxBytes);
            }
            else {
                pcap = getOfflinePcap(_input);
                handler = getSimpleHandler();
            }
        }
        catch (IOException ioexc) {
            logger.severe("Error while opening device for capture: " +
                    ioexc.getMessage());
            return;
        }
        PseudoPacketHandler dumpObject = new PEFPseudonymizeDumper(pcap, destination, pseudonymizer);
        try {
            pcap.loop(Pcap.LOOP_INFINITE, handler, dumpObject);
            if (timed) {
                // A timer for performance tests.
                long stopTime = System.currentTimeMillis();
                logger.info("Stopped after " + ((stopTime - startTime) / 1000.0) + " seconds.");
            }
        }
        catch (NullPointerException e) {
            logger.severe("Error in capturing loop" + e.getMessage());
        }
        finally {
            dumpObject.close();
            pcap.close();
        }
    }

    private static final Pcap getLivePcapStream(final String inputDevice) throws IOException {

        final PcapIf device = getNetworkDevice(inputDevice, false);
        if (device == null) {
            throw new IOException("No suitable device found, select an existing device.");
        }

        // Configuration constants.
        final int snaplen = 64 * 1024;           // Set buffer large enough for complete packets, no truncation
        final int flags = Pcap.MODE_PROMISCUOUS; // Capture all packets that are found.
        final int timeout = 10 * 1000;           // 10 seconds in millis
        // Buffer for c-type errors.
        final StringBuilder errbuf = new StringBuilder();

        // Open the live stream.
        final Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            throw new IOException(errbuf.toString());
        }
        return pcap;
    }

    private static final Pcap getOfflinePcap(final String inputFile) throws IOException {
        final StringBuilder errbuf = new StringBuilder(); // For any error msgs
        final Pcap pcap = Pcap.openOffline(inputFile, errbuf);
        if (pcap == null) {
            throw new IOException(errbuf.toString());
        }
        return pcap;
    }

    /**
     * Creation of a pseudopackethandler packet handler type.
     * Note that used in combination with a infinite loop, will never break.
     *
     * @return returns a packethandler which just 'handles' the packet.
     */
    private static PcapPacketHandler<PseudoPacketHandler> getSimpleHandler() {
        // Packet handler. Generic callback function for PseudoPacketHandler.
        return new PcapPacketHandler<PseudoPacketHandler>() {
            // Handle nextPacket callback.
            public void nextPacket(PcapPacket packet, PseudoPacketHandler handler) {
                handler.handle(packet);
            }
        };
    }

    /**
     * Creation of a pseudopackethandler packet handler type which breaks the loop after.
     *
     * @return returns a packethandler which handles' the packets and stops if the max_bytes amount is handled.
     */
    private static PcapPacketHandler<PseudoPacketHandler> getByteLimitedHandler(final Pcap pcap, final long MAX_BYTES) {
        // Packet handler. Generic callback function for PseudoPacketHandler.
        return new PcapPacketHandler<PseudoPacketHandler>() {
            long packetBytes = 0;

            // Handle nextPacket callback.
            public void nextPacket(PcapPacket packet, PseudoPacketHandler handler) {
                handler.handle(packet);
                packetBytes+= packet.size();
                if (packetBytes >= MAX_BYTES) {
                    pcap.breakloop();
                }
            }
        };
    }

    /**
     * Initialization of the pseudo packet handler which measures the time to handle the configured amount of bytes.
     *
     * @param pcap the interface with the pcap library needed to construct the packet handler.
     * @param MAX_BYTES the maximum amount of bytes captured
     * @return the handler for the packets.
     */
    private static PcapPacketHandler<PseudoPacketHandler> getTimedByteLimitedHandler(final Pcap pcap, final long MAX_BYTES) {
        // Packet handler. Generic callback function for PseudoPacketHandler.
        return new PcapPacketHandler<PseudoPacketHandler>() {
            boolean started = false;
            long packetBytes = 0;
            long startTime;
            long stopTime;

            // A timer for performance tests.
            final ThreadMXBean threadMXBean = ManagementFactory.getThreadMXBean();

            // Handle nextPacket callback.
            public void nextPacket(PcapPacket packet, PseudoPacketHandler handler) {
                if (!started) {
                    startTime = threadMXBean.getCurrentThreadCpuTime();
                    logger.info("Started at "+ startTime);
                    started = true;
                }
                handler.handle(packet);

                packetBytes+= packet.size();
                if (packetBytes >= MAX_BYTES) {
                    stopTime = threadMXBean.getCurrentThreadCpuTime();
                    pcap.breakloop();
                    logger.info("Stopped after " + ((stopTime - startTime)/10000000000.0) + " seconds and " + packetBytes + " bytes.");
                }
            }
        };
    }

    /**
     * Selects the network device to read the data from.
     *
     * @param device the user configured device
     * @param printDevices prints the list of devices.
     * @return the pcap interface device selected
     */
    private static PcapIf getNetworkDevice(final String device, boolean printDevices) {
        List<PcapIf> allDevs = new ArrayList<>();
        final StringBuilder errBuf = new StringBuilder();

        int result = Pcap.findAllDevs(allDevs, errBuf);
        if (result == Pcap.ERROR || allDevs.isEmpty()) {
            if (result == Pcap.ERROR) {
                logger.severe("Can't read list of devices, error is" + errBuf.toString());
            }
            else if (allDevs.isEmpty()) {
                logger.severe("Could not find a suitable device for capturing, check if you have admin rights");
            }
            // Exit application.
            return null;
        }

        //The list is shown, but still the default setting is used.
        if (printDevices) {
            for (final PcapIf dev : allDevs) {
                logger.info(dev.getName());
            }
        }

        if ((device == null) ||  device.equals("")) {
            final PcapIf default_device =  allDevs.get(0);
            logger.info("Default device is used " + default_device.getName());
            return default_device;
        }
        else {
            for (final PcapIf dev : allDevs) {
                if (dev.getName().equals(device)) {
                    return dev;
                }
            }
            logger.severe(device +" is not available in the devices list for live streaming.");
        }
        return null;
    }
}
