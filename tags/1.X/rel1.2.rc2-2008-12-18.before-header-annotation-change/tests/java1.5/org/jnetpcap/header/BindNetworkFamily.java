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
package org.jnetpcap.header;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.MyHeader;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.header.Ethernet;
import org.jnetpcap.packet.header.Icmp;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.packet.header.Payload;
import org.jnetpcap.packet.header.Tcp;

/**
 * A collection of network layer protocol to protocol bindings.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class BindNetworkFamily {

	@Bind(from = Ip4.class, to = Ethernet.class, intValue = 0x800)
	public static boolean bindIp4ToEthernet(JPacket packet, Ethernet eth) {
		return (eth.type() == 0x800);
	}

	@Bind(from = Icmp.class, to = MyHeader.class)
	public static boolean bindIcmpToIp4(JPacket packet, MyHeader ip) {
		return ip.checkType(1);
	}

	@Bind(from = Tcp.class, to = Ip4.class)
	public static boolean bindTcpToIp4(JPacket packet, Ip4 ip) {
		return (ip.type() == 6 && ip.offset() == 0);
	}

	@Bind(from = Payload.class, to = Tcp.class, intValue = 23)
	public static boolean bindTelnetToTcp(JPacket packet, Tcp tcp) {
		return (tcp.source() == 23 || tcp.destination() == 23);
	}

	@Bind(from = Payload.class, to = Tcp.class, intValue = {
	    80,
	    8080 })
	public static boolean bindHttpToTcp(JPacket packet, Tcp tcp) {
		final int s = tcp.source();
		final int d = tcp.destination();
		return s == 80 || d == 80 || s == 8080 || d == 8080;
	}

	@Bind(from = Payload.class, to = Payload.class, stringValue = {
	    "text/html*",
	    "*html*" })
	public static boolean bindHtmlToHttp(JPacket packet, Tcp tcp) {
		return (tcp.source() == 0 || tcp.destination() == 0);
	}
}
