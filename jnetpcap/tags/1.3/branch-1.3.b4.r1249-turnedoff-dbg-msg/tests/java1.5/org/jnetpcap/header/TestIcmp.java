/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.header;

import java.io.IOException;

import junit.framework.TestCase;

import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot1q;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Icmp.IcmpType;
import org.jnetpcap.protocol.tcpip.Udp;

// TODO: Auto-generated Javadoc
/**
 * The Class TestIcmp.
 */
public class TestIcmp
    extends TestCase {

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

	/**
	 * Test icmp dest unreachable.
	 */
	public void testIcmpDestUnreachable() {
		// Wireshark packet # 29 (1-based)
		PcapPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 29 - 1);

		System.out.println(packet.toHexdump(128, false, false, true));
		System.out.println(packet.getState().toDebugString());

		Ip4 ip = new Ip4();
		Icmp icmp = new Icmp(); // Need an instance so we can check on sub header
		Icmp.DestinationUnreachable unreach = new Icmp.DestinationUnreachable();

		assertTrue(packet.hasHeader(Ethernet.ID));
		assertTrue(packet.hasHeader(JProtocol.IP4_ID, 0));
		assertTrue(packet.hasHeader(icmp));
		assertTrue(icmp.hasSubHeader(IcmpType.DESTINATION_UNREACHABLE.getId()));
		assertTrue(icmp.hasSubHeader(unreach));
		assertTrue(packet.hasHeader(ip, 1));
		assertTrue(packet.hasHeader(Udp.ID));
		assertTrue(packet.hasHeader(Payload.ID));

		// Check specific values
		assertEquals(3, icmp.type());
		assertEquals(3, icmp.code());
		assertEquals(0x2731, icmp.checksum());
		assertEquals(0, unreach.reserved());

		assertEquals(0x8724, ip.checksum());
		assertEquals(440, ip.length());

		// Devil's advocate
		assertFalse(icmp.hasSubHeader(IcmpType.ECHO_REPLY.getId()));
		assertFalse(icmp.hasSubHeader(IcmpType.PARAM_PROBLEM.getId()));

	}

	/**
	 * Test icmp echo request.
	 */
	public void testIcmpEchoRequest() {
		// Wireshark packet # 58 (1-based)
		PcapPacket packet = TestUtils.getPcapPacket("tests/test-vlan.pcap", 58 - 1);

		System.out.println(packet.toString());

		Icmp icmp = new Icmp(); // Need an instance so we can check on sub header
		Icmp.EchoRequest echo = new Icmp.EchoRequest();

		assertTrue(packet.hasHeader(Ethernet.ID));
		assertTrue(packet.hasHeader(IEEE802dot1q.ID, 0));
		assertTrue(packet.hasHeader(Ip4.ID));
		assertTrue(packet.hasHeader(icmp));
		assertTrue(icmp.hasSubHeader(echo));

		assertEquals(8, icmp.type());
		assertEquals(0, icmp.code());
		assertEquals(0x10FD, icmp.checksum());

		assertEquals(0xd001, echo.id());
		assertEquals(0x811e, echo.sequence());

		// Devil's advocate
		assertFalse(icmp.hasSubHeader(IcmpType.ECHO_REPLY.id));
		assertFalse(icmp.hasSubHeader(IcmpType.PARAM_PROBLEM.id));

	}

	/**
	 * Test icmp echo reply.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void testIcmpEchoReply() throws IOException {
		// Wireshark packet # 59 (1-based)
		PcapPacket packet = TestUtils.getPcapPacket("tests/test-vlan.pcap", 59 - 1);

//		System.out.println(packet.toString());

		Icmp icmp = new Icmp(); // Need an instance so we can check on sub header
		Icmp.EchoReply echo = new Icmp.EchoReply();

		assertTrue(packet.hasHeader(Ethernet.ID));
		assertTrue(packet.hasHeader(IEEE802dot1q.ID, 0));
		assertTrue(packet.hasHeader(Ip4.ID));
		assertTrue(packet.hasHeader(icmp));
		assertTrue(icmp.hasSubHeader(echo));

		@SuppressWarnings("unused")
    TextFormatter out = new TextFormatter();
//		out.format(echo, Detail.MULTI_LINE_FULL_DETAIL);

		assertEquals(0, icmp.type());
		assertEquals(0, icmp.code());
		assertEquals(0x18FD, icmp.checksum());

		assertEquals(0xd001, echo.id());
		assertEquals(0x811e, echo.sequence());

		// Devil's advocate
		assertTrue(icmp.hasSubHeader(IcmpType.ECHO_REPLY.id));
		assertFalse(icmp.hasSubHeader(IcmpType.ECHO_REQUEST.id));
		assertFalse(icmp.hasSubHeader(IcmpType.PARAM_PROBLEM.id));

	}

}
