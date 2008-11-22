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
package org.jnetpcap.packet;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.BetaFeature;
import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;

/**
 * This example is the classic libpcap example shown in nearly every tutorial on
 * libpcap. It gets a list of network devices, presents a simple ASCII based
 * menu and waits for user to select one of those interfaces. We will just
 * select the first interface in the list instead of taking input to shorten the
 * example. Then it opens that interface for live capture. Using a packet
 * handler it goes into a loop to catch a few packets, say 10. Prints some
 * simple info about the packets, and then closes the pcap handle and exits.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class ClassicPcapExampleUsingJPacket {

	public static void main(String[] args) {
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

		PcapIf device = alldevs.get(2); // We know we have atleast 1 device
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
		JPacketHandler<String> printSummaryHandler = new JPacketHandler<String>() {

			private JFormatter output = new TextFormatter(); // To System.out

			public void nextPacket(JPacket packet, String user) {
				final JCaptureHeader header = packet.getCaptureHeader();

				System.out.printf("Packet captured on %s\n", new Timestamp(header
				    .timestampInMillis()));

				try {
					output.format(packet); // Sends formatted output to System.out
				} catch (IOException e) {// Any IO errors with System.out
					e.printStackTrace();
				}
			}
		};

		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets Notice that
		 * since this is a beta feature currently, not fully integrated into
		 * production Pcap class, we have to supply the pcap object as a parameter,
		 * we also need to specify the data link protocol of the interface which is
		 * Ethernet in our example. This is needed so that the packet scanner
		 * (JScanner) knows how to decode the buffer it receives.
		 **************************************************************************/
		BetaFeature.loop(pcap, 10, JProtocol.ETHERNET_ID, printSummaryHandler,
		    "jNetPcap rocks!");

		/*
		 * Last thing to do is close the pcap handle
		 */
		pcap.close();
	}
}
