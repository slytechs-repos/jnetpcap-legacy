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
package org.jnetpcap.bugs;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;

/**
 * 2828030 JMemoryPacket doesn't set wirelen.
 * <p>
 * Several JMemoryPacket constructors do not set the required "wirelen" header
 * property. This causes exceptions to be thrown by the quick-scanner.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Bug2832692_null_ptr_in_hasHeader
    extends
    TestUtils {

	private final static String BUG_FILE =   TestUtils.L2TP;

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
	 * Tests if RouterAlert Ip4 optional header is found and peered properly.
	 */
	public void testIp4OptionRouterAlert() {
		String data =
		    "" + " 01 00 5e 00  00 16 00 03  ff 2a 7a 6c  08 00 46 00"
		        + " 00 28 d7 04  00 00 01 02  ac fa c0 a8  00 12 e0 00"
		        + " 00 16 94 04  00 00 22 00  ea 03 00 00  00 01 04 00"
		        + " 00 00 ef ff  ff fa 00 00  00 00 00 00             " + "";
		JMemoryPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, data);
		Ip4 ip = new Ip4();
		Ip4.RouterAlert alert = new Ip4.RouterAlert();
		assertTrue(packet.hasHeader(ip));
		assertTrue(ip.hasSubHeader(alert));

		System.out.println(alert);
	}
}
