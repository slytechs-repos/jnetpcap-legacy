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
package org.jnetpcap.packet;

/**
 * A dispatchable packet hadler. The handler receives fully decoded packets from
 * libpcap library.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JPacketHandler<T> {

	/**
	 * Callback function called on by libpcap and jNetPcap scanner once a new
	 * packet arrives and has passed the set BPF filter. The packet object
	 * dispatched is not allocated on a per call basis, but is shared between
	 * every call made. At the time the pcap dispatch or loop is established a
	 * freshly allocated packet is used to peer with received packet buffers from
	 * libpcap, scanned then dispatched to this method for the user to process.
	 * The packet memory and state is not persistent between calls. If a more
	 * persistent state is need it must be copied outof the supplied packet into a
	 * more permanent packet.
	 * 
	 * <pre>
	 * public void nextPacket(JPacket packet, T user) {
	 * 	JPacket permanentPacket = new JPacket(packet);// creates a permanent packet
	 * }
	 * </pre>
	 * 
	 * @param packet
	 *          a non persistent between invokations decoded packet
	 * @param user
	 *          user supplied object of type <T>
	 */
	public void nextPacket(JPacket packet, T user);

}
