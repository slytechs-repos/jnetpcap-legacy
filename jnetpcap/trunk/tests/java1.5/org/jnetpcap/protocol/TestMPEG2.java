/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.protocol;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.protocol.iso.MPEG2;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestMPEG2
    extends
    TestUtils {
	static {
		try {
			JRegistry.register(MPEG2.class);

			JRegistry.addBindings(new Object() {

				@SuppressWarnings("unused")
				@Bind(from = MPEG2.class, to = Udp.class)
				public boolean bindMPEG2ToIp4(JPacket packet, Udp udp) {
					return udp.destination() == 6000;
				}

				@SuppressWarnings("unused")
				@Bind(from = MPEG2.class, to = MPEG2.class)
				public boolean bindMPEG2ToMPEG2(JPacket packet, MPEG2 mpeg) {
					return true; // Its a non-stop chain of MPEG2 headers
				}

			});
		} catch (RegistryHeaderErrors e) {
			e.printStackTrace();
			System.exit(1);
		}

		System.out.println(JRegistry.toDebugString());
	}

	public final static String UAV = "tests/UAV_GPS.pcap";

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	public void testMPEG2TSHeader() {

		Pcap pcap = TestUtils.openOffline(UAV);

//		 PcapBpfProgram bpf = new PcapBpfProgram();
//		 pcap.compile(bpf, "icmp", 1, 0);
//		 pcap.setFilter(bpf);

//		pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<Object>() {
			pcap.loop(1, new PcapPacketHandler<Object>() {

			private int i = 0;

			private final Udp udp = new Udp();

			private final Ethernet eth = new Ethernet();

			private final Ip4 ip1 = new Ip4();
			private final Ip4 ip2 = new Ip4();

			private final Icmp icmp = new Icmp();

			public void nextPacket(PcapPacket packet, Object user) {

				// packet = new PcapPacket(packet);

//				packet.scan();

				// if (packet.hasHeader(udp)) {
				//
				// System.out.printf("#%d port=%d size=%d payload=%d%n", packet
				// .getFrameNumber(), udp.destination(), udp.size(), udp
				// .getPayload().length);
				// System.out.println(packet.getState().toDebugString());
				// System.out.println(udp);
				// }

//				System.out.println(packet.getState().toDebugString());
				System.out.println(packet);
				if (packet.hasHeader(eth) && packet.hasHeader(ip1, 0) && packet.hasHeader(ip2, 1)
				    && packet.hasHeader(icmp) && packet.hasHeader(udp)) {
//					System.out.println(eth);
//					System.out.println(ip1);
//					System.out.println(ip2);
//					System.out.println(icmp);
//					System.out.println(udp);
				}

				if (i++ % 100 == 0) {
					System.out.printf("%3d ", i);
					System.out.flush();
				}

				if (i % 1000 == 0) {
					System.out.println();
				}
			}
		}, null);

		pcap.close();
	}
}
