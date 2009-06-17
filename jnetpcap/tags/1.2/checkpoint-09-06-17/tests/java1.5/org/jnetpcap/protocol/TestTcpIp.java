/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.checksum.Checksum;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestTcpIp
    extends
    TestUtils {

	public final static String HTTP_IP6 = "tests/v6-http.cap";

	public void testIp4CRC16Pkt1() {

		JPacket packet = super.getPcapPacket(TestUtils.L2TP, 0);
		Ip4 ip = packet.getHeader(new Ip4());

		assertEquals(Checksum.ip2Chunk(ip, 0, 10, 12, ip.size() - 12), ip
		    .checksum());
	}

	public void testIp4CRC16Pkt2() {

		JPacket packet = super.getPcapPacket(TestUtils.L2TP, 1);
		Ip4 ip = packet.getHeader(new Ip4());

		assertEquals(Checksum.ip2Chunk(ip, 0, 10, 12, ip.size() - 12), ip
		    .checksum());
	}

	public void testIp4CRC16Pkt50() {

		JPacket packet = super.getPcapPacket(TestUtils.L2TP, 46 - 1);
		Ip4 ip = packet.getHeader(new Ip4());

		int crc;
		assertEquals(crc = Checksum.ip2Chunk(ip, 0, 10, 12, ip.size() - 12), ip
		    .checksum());

		System.out.printf("ip.crc=%x computed=%x\n", ip.checksum(), crc);
	}

	public void testIp4CRC16EntireFile() throws InterruptedException {
		Ip4 ip = new Ip4();
		for (JPacket packet : super.getIterable(TestUtils.L2TP)) {
			Thread.sleep(10);
			long f = packet.getFrameNumber() + 1;
			assertTrue(packet.hasHeader(ip));

			assertEquals(20, ip.size());
			final int crc = Checksum.ip2Chunk(ip, 0, 10, 12, ip.size() - 12);
			assertEquals(Checksum.ip2Chunk(ip, 0, 10, 12, ip.size() - 12), Checksum
			    .ip2Chunk(ip, 0, 10, 12, ip.size() - 12));

			if (ip.checksum() != crc) {
				System.out.println(packet);
				System.out
				    .printf("#%d: ip.crc=%x computed=%x\n", f, ip.checksum(), crc);
				System.out.println(ip.toHexdump());
			}

			assertEquals("Frame #" + f, ip.checksum(), crc);
		}
	}

	public void testIp4CRC16UsingHandler() {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(TestUtils.L2TP, errbuf);

		assertNotNull(pcap);

		pcap.loop(Pcap.LOOP_INFINATE, new PcapPacketHandler<String>() {
			Ip4 ip = new Ip4();

			// public void nextPacket(PcapHeader header, JBuffer buffer, String user)
			// {
			public void nextPacket(PcapPacket packet, String user) {

				// PcapPacket packet = new PcapPacket(header, buffer);

				long f = packet.getFrameNumber();
				assertTrue("#" + f, packet.hasHeader(ip));

				final int crc = Checksum.ip2Chunk(ip, 0, 10, 12, ip.size() - 12);
				// final int crc = Checksum.ip1Chunk(ip, 0, ip.size());

				if (crc != 0 && ip.checksum() != crc) {
					System.out.println(packet);
					System.out.printf("#%d: ip.crc=%x computed=%x\n", f, ip.checksum(),
					    crc);
					System.out.println(ip.toHexdump());
				}
				// assertEquals("Frame #" + f, 0, crc);

				assertEquals("Frame #" + f, ip.checksum(), crc);
			}

		}, null);
	}

	public void testTcpIp4CRC16UsingHandler() {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(TestUtils.HTTP, errbuf);

		assertNotNull(errbuf.toString(), pcap);

		pcap.loop(Pcap.LOOP_INFINATE, new PcapPacketHandler<String>() {
			Ip4 ip = new Ip4();

			Tcp tcp = new Tcp();

			// public void nextPacket(PcapHeader header, JBuffer buffer, String user)
			// {
			public void nextPacket(PcapPacket packet, String user) {

				if (packet.hasHeader(tcp) == false) {
					return;
				}

				// PcapPacket packet = new PcapPacket(header, buffer);

				long f = packet.getFrameNumber();
				assertTrue("#" + f, packet.hasHeader(ip));

				final int crc =
				    Checksum.pseudoTcp(packet, ip.getOffset(), tcp.getOffset());

				if (crc != 0 && tcp.checksum() != crc) {
					System.out.println(tcp);
					System.out.printf("#%d: tcp.crc=%x computed=%x\n", f, tcp.checksum(),
					    crc);
					// System.out.println(ip.toHexdump());
					// System.out.println(tcp.toHexdump());
					System.exit(0);
				}

				// assertEquals("Frame #" + f, tcp.checksum(), crc);
			}

		}, null);
	}

	public void testTcpIp6CRC16UsingHandler() {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(HTTP_IP6, errbuf);

		assertNotNull(errbuf.toString(), pcap);

		pcap.loop(Pcap.LOOP_INFINATE, new PcapPacketHandler<String>() {
			Ip6 ip = new Ip6();

			Tcp tcp = new Tcp();

			public void nextPacket(PcapPacket packet, String user) {

				if (packet.hasHeader(tcp) == false) {
					return;
				}

				// PcapPacket packet = new PcapPacket(header, buffer);

				long f = packet.getFrameNumber();
				assertTrue("#" + f, packet.hasHeader(ip));

				final int crc =
				    Checksum.pseudoTcp(packet, ip.getOffset(), tcp.getOffset());

				if (crc != 0 && tcp.checksum() != crc) {
					System.out.println(tcp);
					System.out.printf("#%d: tcp.crc=%x computed=%x\n", f, tcp.checksum(),
					    crc);
					// System.out.println(ip.toHexdump());
					// System.out.println(tcp.toHexdump());
					System.exit(0);
				}

				assertEquals("Frame #" + f, tcp.checksum(), crc);
			}

		}, null);
	}

	public void testUdpIp6CRC16UsingHandler() {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(HTTP_IP6, errbuf);

		assertNotNull(errbuf.toString(), pcap);

		pcap.loop(Pcap.LOOP_INFINATE, new PcapPacketHandler<String>() {
			Ip6 ip = new Ip6();

			Udp udp = new Udp();

			public void nextPacket(PcapPacket packet, String user) {

				if (packet.hasHeader(udp) == false) {
					return;
				}

				// PcapPacket packet = new PcapPacket(header, buffer);

				long f = packet.getFrameNumber();
				assertTrue("#" + f, packet.hasHeader(ip));

				final int crc =
				    Checksum.pseudoUdp(packet, ip.getOffset(), udp.getOffset());

				if (crc != 0 && udp.checksum() != crc) {
					System.out.println(udp);
					System.out.printf("#%d: udp.crc=%x computed=%x\n", f, udp.checksum(),
					    crc);
					// System.out.println(ip.toHexdump());
					// System.out.println(tcp.toHexdump());
					System.exit(0);
				}

				assertEquals("Frame #" + f, udp.checksum(), crc);
			}

		}, null);
	}

	public void testIcmpCRC16UsingHandler() {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(TestTcpIp.VLAN, errbuf);

		assertNotNull(errbuf.toString(), pcap);

		pcap.loop(Pcap.LOOP_INFINATE, new PcapPacketHandler<String>() {
			Ip4 ip = new Ip4();

			Icmp icmp = new Icmp();

			public void nextPacket(PcapPacket packet, String user) {

				if (packet.hasHeader(icmp) == false) {
					return;
				}

				// PcapPacket packet = new PcapPacket(header, buffer);

				long f = packet.getFrameNumber();
				assertTrue("#" + f, packet.hasHeader(ip));

				final int crc = Checksum.icmp(packet, ip.getOffset(), icmp.getOffset());

				if (ip.isFragment() == false && crc != 0 && icmp.checksum() != crc) {
					System.out.println(packet);
					System.out.printf("#%d: udp.crc=%x computed=%x\n", f,
					    icmp.checksum(), crc);
					// System.out.println(ip.toHexdump());
					// System.out.println(tcp.toHexdump());

					System.out.flush();
					System.exit(0);
				}
			}

		}, null);
	}

	public void testIp4FragmentFlagDirectly() {
		JPacket packet = TestUtils.getPcapPacket(TestUtils.REASEMBLY, 1 - 1);
		Ethernet eth = new Ethernet();
		
		if (packet.hasHeader(eth)) {
//			System.out.println(eth);
//			System.out.printf("flags=%x\n", eth.getState().getFlags());
			assertNotSame(JHeader.State.FLAG_HEADER_FRAGMENTED, (eth.getState()
			    .getFlags() & JHeader.State.FLAG_HEADER_FRAGMENTED));
		}

		Ip4 ip = new Ip4();
		if (packet.hasHeader(ip)) {
//			System.out.println(ip);
//			System.out.printf("flags=%x\n", ip.getState().getFlags());
			assertEquals(JHeader.State.FLAG_HEADER_FRAGMENTED, (ip.getState()
			    .getFlags() & JHeader.State.FLAG_HEADER_FRAGMENTED));
		}
		
		Icmp icmp = new Icmp();
		if (packet.hasHeader(icmp)) {
//			System.out.println(icmp);
//			System.out.printf("flags=%x\n", icmp.getState().getFlags());
			assertEquals(JHeader.State.FLAG_HEADER_FRAGMENTED, (icmp.getState()
			    .getFlags() & JHeader.State.FLAG_HEADER_FRAGMENTED));
		}

	}
	
	public void testJHeaderIsFragmented() {
		JPacket packet = TestUtils.getPcapPacket(TestUtils.REASEMBLY, 1 - 1);
		Ethernet eth = new Ethernet();
		
		if (packet.hasHeader(eth)) {
			assertFalse(eth.isFragmented());
		}

		Ip4 ip = new Ip4();
		if (packet.hasHeader(ip)) {
			assertTrue(ip.isFragmented());
		}
		
		Icmp icmp = new Icmp();
		if (packet.hasHeader(icmp)) {
			assertTrue(ip.isFragmented());
		}

	}

}
