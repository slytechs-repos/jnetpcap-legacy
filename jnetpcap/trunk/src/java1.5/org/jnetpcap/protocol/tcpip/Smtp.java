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
package org.jnetpcap.protocol.tcpip;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.network.Ip4;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @author Mehmet Emin PACA
 */
public class Smtp
    extends
    JHeader {
	private int length = 0;

	private static Ip4 ip = new Ip4();

	private static Tcp tcp = new Tcp();

	@HeaderLength
	public int headerLength() {

		getPacket().getHeader(ip);
		getPacket().getHeader(tcp);

		length = ip.length() - ip.hlen() * 4 - tcp.hlen() * 4;

		return length;
	}

	public String getMessage() {

		byte[] byteArray = super.getByteArray(0, length);

		String message = new String(byteArray);

		return message;
	}

	@Bind(to = Tcp.class)
	public static boolean bindToTcp() {

		return (tcp.source() == 25 || tcp.destination() == 25);
	}
}
