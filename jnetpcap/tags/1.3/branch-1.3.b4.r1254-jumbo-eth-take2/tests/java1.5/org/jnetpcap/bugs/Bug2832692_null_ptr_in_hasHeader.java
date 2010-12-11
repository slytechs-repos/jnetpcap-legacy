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

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;

// TODO: Auto-generated Javadoc
/**
 * The Class Bug2832692_null_ptr_in_hasHeader.
 */
public class Bug2832692_null_ptr_in_hasHeader
    extends
    TestUtils {

	/** The Constant BUG_FILE. */
	private final static String BUG_FILE = TestUtils.L2TP;

	/**
	 * SKI p_test read entire suspect file.
	 */
	public void SKIP_testReadEntireSuspectFile() {

		Ip4 ip = new Ip4();
		for (PcapPacket packet : TestUtils.getIterable(BUG_FILE)) {
			try {
				if (packet.getFrameNumber() == 15) {
					System.out.println(packet);
					System.out.println(packet
					    .toHexdump(packet.size(), false, false, true));
				}

				packet.hasHeader(ip);
			} catch (NullPointerException e) {
				System.out.println(packet.getState().toDebugString());
				System.out.println(packet.toHexdump());

				throw e;
			}
		}
	}

	/**
	 * Test ip4 option router alert.
	 */
	public void testIp4OptionRouterAlert() {
		String data =
		    " 01 00 5e 00  00 16 00 03  ff 2a 7a 6c  08 00 46 00"
		        + " 00 28 d7 04  00 00 01 02  ac fa c0 a8  00 12 e0 00"
		        + " 00 16 94 04  00 00 22 00  ea 03 00 00  00 01 04 00"
		        + " 00 00 ef ff  ff fa 00 00  00 00 00 00             ";
		JMemoryPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, data);
		Ip4 ip = new Ip4();
		Ip4.RouterAlert alert = new Ip4.RouterAlert();
		
		assertTrue(packet.hasHeader(ip));
		assertTrue(ip.hasSubHeader(alert));

		System.out.println(alert);
	}
}
