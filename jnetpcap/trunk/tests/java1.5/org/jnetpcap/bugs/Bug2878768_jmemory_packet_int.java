/**
 * Copyright (C) 2009 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jnetpcap.bugs;

import java.nio.ByteOrder;

import junit.framework.TestCase;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class Bug2878768_jmemory_packet_int
    extends
    TestCase {

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}
	
	public void test1() {
		
		JMemoryPacket packet = new JMemoryPacket(64);
		packet.order(ByteOrder.BIG_ENDIAN);
		
		packet.setUShort(0 + 12, 0x800); // ethernet.type field
		packet.setUByte(14 + 0, 0x45); // ip.version and ip.hlen fields
		packet.setUShort(14 + 9, 0x6); // ip.type = TCP, and so on
		packet.scan(JProtocol.ETHERNET_ID); // Scans the packet which will allow us
		
		System.out.println(packet.toHexdump());
		System.out.println(packet.getState().toDebugString());
		Ethernet eth = packet.getHeader(new Ethernet());
		assertNotNull(eth);
		
		System.out.println(eth);
		/*
		 * JPacket packet = new JMemoryPacket(1400);
packet.setUShort(0 + 12, 0x800); // ethernet.type field
packet.setUByte(14 + 0, 0x45);   // ip.version and ip.hlen fields
packet.setUShort(14 + 9, 0x6);   // ip.type = TCP, and so on
packet.scan(JProtocol.ETHERNET_ID); // Scans the packet which will allow us
to peer headers
// Now peer our headers, also could have used JPacket.hasHeader()
Ethernet eth = packet.getHeader(new Ethernet());

Throws - > Exception in thread "main" java.lang.NullPointerException: JBuffer
not initialized

Now if I change to JBuffer() I get past the nullpointer but eth is always
null.
JPacket packet = new JMemoryPacket(new JBuffer(1400));
packet.setUShort(0 + 12, 0x800); // ethernet.type field
packet.setUByte(14 + 0, 0x45);   // ip.version and ip.hlen fields
packet.setUShort(14 + 9, 0x6);   // ip.type = TCP, and so on
packet.scan(JProtocol.ETHERNET_ID); // Scans the packet which will allow us
to peer headers
// Now peer our headers, also could have used JPacket.hasHeader()
Ethernet eth = packet.getHeader(new Ethernet());

		 */
		
	}

}
