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
package org.jnetpcap.protocol;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Rip1;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class TestNetwork
    extends
    TestUtils {
	
	public final static String RIP_V1 = "tests/Rip_V1.pcap";


	public void testArp() {
		JPacket packet = super.getPcapPacket(VLAN, 189 - 1);
		
		assertTrue(packet.hasHeader(JProtocol.ARP_ID));
		
		Arp arp = new Arp();
		assertTrue(packet.hasHeader(arp));
		assertEquals(Arp.OpCode.REQUEST, arp.operationEnum());
	}
	
	public void SKIPtestRip1() throws RegistryHeaderErrors {
		final int RIP1_ID = JRegistry.register(Rip1.class);
		
		JPacket packet = super.getPcapPacket(RIP_V1, 1 - 1);
		
		assertTrue(packet.hasHeader(RIP1_ID));
		
		Rip1 rip = new Rip1();
		
		System.out.println(packet);
		
	}
}
