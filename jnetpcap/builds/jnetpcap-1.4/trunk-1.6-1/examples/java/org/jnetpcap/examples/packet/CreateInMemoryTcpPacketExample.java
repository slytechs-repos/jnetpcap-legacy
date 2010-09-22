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
package org.jnetpcap.examples.packet;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 * Example create a in memory IMAP packet.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class CreateInMemoryTcpPacketExample {

	/**
	 * Creates a packet and formats it for text output. The example modifies the
	 * tcp.destination port to 80 and recalculates both ip and tcp header
	 * checksums.
	 * 
	 * @param args
	 *          none expected
	 */
	public static void main(String[] args) {
		JPacket packet =
		    new JMemoryPacket(JProtocol.ETHERNET_ID,
		        " 001801bf 6adc0025 4bb7afec 08004500 "
		            + " 0041a983 40004006 d69ac0a8 00342f8c "
		            + " ca30c3ef 008f2e80 11f52ea8 4b578018 "
		            + " ffffa6ea 00000101 080a152e ef03002a "
		            + " 2c943538 322e3430 204e4f4f 500d0a");

		Ip4 ip = packet.getHeader(new Ip4());
		Tcp tcp = packet.getHeader(new Tcp());

		tcp.destination(80);

		ip.checksum(ip.calculateChecksum());
		tcp.checksum(tcp.calculateChecksum());
		packet.scan(Ethernet.ID);

		System.out.println(packet);
	}
}
