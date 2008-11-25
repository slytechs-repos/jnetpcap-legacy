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

import java.nio.ByteBuffer;

import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemoryPool;

/**
 * A pcap packet. A pcap packet has a PcapHeader, a capture header.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapPacket
    extends JPacket {

	private final PcapHeader captureHeader = new PcapHeader();

	/**
	 * Special type of instantiation that allows an empty packet to be peered, or
	 * in C terms its a packet pointer with no actual memory allocated.
	 */
	public PcapPacket(Type type) {
		super(type);
	}

	/**
	 * Creates a packet object and peers its data buffer with the supplied buffer
	 * 
	 * @param buffer
	 *          packet data buffer
	 */
	public PcapPacket(ByteBuffer buffer) {
		super(buffer);
	}

	/**
	 * Allocates a packet with a native memory to hold packet data
	 * 
	 * @param size
	 *          nubmer of bytes to allocate for packet data buffer
	 */
	public PcapPacket(int size) {
		super(size);
	}

	/**
	 * Creates a packet object and peers its data buffer with the supplied buffer
	 * 
	 * @param buffer
	 *          packet data buffer
	 */
	public PcapPacket(JBuffer buffer) {
		super(buffer);
	}

	/**
	 * Does a deep copy of the source packet into newly allocated native memory
	 * location
	 * 
	 * @param src
	 *          source packet
	 */
	public PcapPacket(JPacket src) {
		super(src);
	}

	/**
	 * Does a deep copy of the source packet into newly allocated native memory
	 * location
	 * 
	 * @param src
	 *          source packet
	 * @param pool
	 *          memory pool to use to allocate memory for the deep copy
	 */
	public PcapPacket(JPacket src, JMemoryPool pool) {
		super(src, pool);
	}

	/**
	 * Retrieves the PcapHeader, capture header provided by libpcap
	 * 
	 * @return capture header
	 */
	@Override
	public PcapHeader getCaptureHeader() {
		return captureHeader;
	}

	/**
	 * Peer the supplied header with this header
	 * 
	 * @param header
	 *          destination capture header to peer with
	 * @return number of bytes peered
	 */
	public int peer(PcapHeader header) {
		return captureHeader.peer(header);
	}
}
