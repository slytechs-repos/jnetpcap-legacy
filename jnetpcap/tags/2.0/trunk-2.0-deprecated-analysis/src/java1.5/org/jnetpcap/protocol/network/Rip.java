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
package org.jnetpcap.protocol.network;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * Routing Information Protocol (RIP). This is a baseclass for subclasses Rip1
 * and Rip2 which parse rip version 1 and version 2 protocols.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(suite = ProtocolSuite.TCP_IP, description = "Routing Information Protocol")
public abstract class Rip
    extends
    JHeader {

	/**
	 * Valid values for RIP OpCode field.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Command {
		REQUEST,
		REPLY,
		TRACE_ON,
		TRACE_OFF,
		SUN,
		TRIGGERED_REQUEST,
		TRIGGERED_RESPONSE,
		TRIGGERED_ACK,
		UPDATE_REQUEST,
		UPDATE_RESPONSE,
		UPDATE_ACK;

		public static Command valueOf(final int value) {
			return (value < values().length) ? values()[value] : null;
		}
	}

	/**
	 * Bind to UDP port 520 which is the default for RIP.
	 * 
	 * @param packet
	 *          current packet
	 * @param udp
	 *          udp header within this packet
	 * @return true if binding succeeded or false if failed
	 */
	@Bind(to = Udp.class)
	public static boolean bindToUdp(
	    final JPacket packet,
	    final org.jnetpcap.protocol.tcpip.Udp udp) {
		return (udp.destination() == 520) || (udp.source() == 520);
	}

	@HeaderLength
	public static int headerLength(final JBuffer buffer, final int offset) {
		return buffer.size() - offset;
	}

	protected int count;

	@Field(offset = 0, length = 8)
	public int command() {
		return super.getUByte(0);
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String commandDescription() {
		return commandEnum().toString();
	}

	public Command commandEnum() {
		return Command.valueOf(command());
	}

	/**
	 * Gets the number of entries in the routing table
	 * 
	 * @return count of number of 20 byte entries in the routing table
	 */
	public int count() {
		return this.count;
	}

	/**
	 * The routing table is the only thing that needs decoding. The routing table
	 * is lazy decoded using {@link Rip#decodeRoutingTable()} which only then
	 * creates routing table entries.
	 */
	@Override
	protected void decodeHeader() {
		this.count = (size() - 4) / 20;
	}

	@Field(offset = 8, length = 8)
	public int version() {
		return super.getUByte(1);
	}

}
