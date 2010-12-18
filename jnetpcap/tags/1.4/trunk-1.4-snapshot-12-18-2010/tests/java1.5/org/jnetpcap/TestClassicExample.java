/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
 * can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package org.jnetpcap;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
public class TestClassicExample
    extends TestCase {

	/**
	 * @throws java.lang.Exception
	 */

	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */

	public void tearDown() throws Exception {
	}

	public void testInfiniteLoopForProfiling() {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}

		System.out.println("Network devices found:");

		int i = 0;
		for (PcapIf device : alldevs) {
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), device
			    .getDescription());
		}

		PcapIf device = alldevs.get(0); // We know we have atleast 1 device
		System.out.printf("\nChoosing '%s' on your behalf:\n", device
		    .getDescription());

		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis
		Pcap pcap =
		    Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}

		/***************************************************************************
		 * Third we create a packet hander which will be dispatched to from the
		 * libpcap loop.
		 **************************************************************************/
		PcapHandler<String> printSummaryHandler = new PcapHandler<String>() {

			public void nextPacket(String user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {
				Date timestamp = new Date(seconds * 1000 + useconds / 1000); // In
																																			// millis

				System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
				    timestamp.toString(), // timestamp to 1 ms accuracy
				    caplen, // Length actually captured
				    len, // Original length of the packet
				    user // User supplied object
				    );
			}
		};

		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets
		 **************************************************************************/
		pcap.loop(10, printSummaryHandler, "jNetPcap rocks!");

		/*
		 * Last thing to do is close the pcap handle
		 */
		pcap.close();

	}

}
