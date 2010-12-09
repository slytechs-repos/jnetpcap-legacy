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
package org.jnetpcap.bugs;

import junit.framework.TestCase;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Class Bug2899902_BufferUnderFlow_in_Tcp_DecodeHeader.
 */
public class Bug2899902_BufferUnderFlow_in_Tcp_DecodeHeader
    extends
    TestCase {

	/**
	 * Test bug2899902.
	 */
	public void testBug2899902() {

		String packetData =
		    "00 0a 8a 27 b8 80 00 30 48 32 72 86 08 00 45 00 "
		        + "00 40 d8 d5 40 00 40 06 2f 80 55 5e 40 14 c3 1d "
		        + "d9 d2 00 6e 06 86 c4 53 d9 dd 7c e1 ce 2c 50 18 "
		        + "16 d0 73 4b 00 00 2b 4f 4b 20 50 61 73 73 77 6f "
		        + "72 64 20 72 65 71 75 69 72 65 64 2e 0d 0a";
		
		JMemoryPacket p = new JMemoryPacket(JProtocol.ETHERNET_ID, packetData);
		TextFormatter.getDefault().setResolveAddresses(true);
		System.out.println(p);
	}

}
