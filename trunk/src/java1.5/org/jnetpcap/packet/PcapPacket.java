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

import org.jnetpcap.IncompatiblePeer;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemoryPool.Block.Malloced;

/**
 * A pcap packet. A pcap packet has a PcapHeader, a capture header.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapPacket
    extends JPacket {

	private final static int STATE_SIZE =
	    PcapHeader.sizeof() + JPacket.State.sizeof(DEFAULT_STATE_HEADER_COUNT);

	private final PcapHeader header = new PcapHeader(Type.POINTER);

	/**
	 * Copies contents of the buffer to new packet. All of the contents of the
	 * buffer are deep copied to new packet.
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * Will result in new buffer layout:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 */
	public PcapPacket(byte[] buffer) {
		super(Type.POINTER);

		transferFrom(buffer);
	}

	/**
	 * Copies contents of the buffer to new packet. All of the contents of the
	 * buffer are deep copied to new packet.
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * Will result in new buffer layout:
	 * 
	 * <pre>
	 * +----------+-----+----+
	 * |PcapHeader|State|Data|
	 * +----------+-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 */
	public PcapPacket(ByteBuffer buffer) {
		super(Type.POINTER);

		if (buffer.isDirect()) {
			peer(buffer);
		} else {
			transferFrom(buffer.array());
		}
	}

	/**
	 * Allocates a memory buffer large enough to hold atleast size bytes of data
	 * and the decoded packet state. The size of the the state structure is
	 * estimated to contain maximum of {@literal DEFAULT_STATE_HEADER_COUNT}
	 * headers.
	 * 
	 * @param size
	 *          amount of memory to allocate to hold packet data
	 */
	public PcapPacket(int size) {
		super(size, STATE_SIZE);
	}

	/**
	 * Allocates memory for packet data and certain amount of state and headers
	 * 
	 * @param size
	 *          number of bytes for packet data
	 * @param headerCount
	 *          maximum number of header to allocate space for
	 */
	public PcapPacket(int size, int headerCount) {
		super(size, PcapHeader.sizeof() + JPacket.State.sizeof(headerCount));
	}

	/**
	 * Creates a packet object and peers its data buffer with the supplied buffer
	 * 
	 * @param buffer
	 *          packet data buffer
	 */
	public PcapPacket(JBuffer buffer) {
		super(Type.POINTER);

		peer(buffer);
	}

	/**
	 * Does a deep copy of the source packet into newly allocated native memory
	 * location
	 * 
	 * @param src
	 *          source packet
	 * @throws IncompatiblePeer
	 */
	public PcapPacket(PcapPacket src) {
		super(Type.POINTER);

		src.transferTo(this);
	}

	/**
	 * Special type of instantiation that allows an empty packet to be peered, or
	 * in C terms its a packet pointer with no actual memory allocated.
	 */
	public PcapPacket(Type type) {
		super(type);
	}

	/**
	 * Creates an uninitialized packet that has its capture header and packet data
	 * buffer set. The packet state has not been decoded and accessing certain
	 * methods may throw NullPointerException.
	 * 
	 * @param header capture header
	 * @param buffer packet data buffer
	 */
	public PcapPacket(PcapHeader header, JBuffer buffer) {
		super(Type.POINTER);

		this.header.peerTo(header, 0);
		super.peer(buffer);
	}

	/**
	 * Retrieves the PcapHeader, capture header provided by libpcap
	 * 
	 * @return capture header
	 */
	@Override
	public PcapHeader getCaptureHeader() {
		return header;
	}

	public int getTotalSize() {
		return super.size() + state.size() + header.size();
	}

	/**
	 * 
	 */
	public int peer(ByteBuffer buffer) {
		return peer(getMemoryBuffer(buffer), 0);
	}

	public int peer(JBuffer buffer) {
		return peer(getMemoryBuffer(buffer), 0);
	}

	private int peer(Malloced memory, int offset) {

		int o = header.peer(memory, offset);
		state.peerTo(memory, offset + o, State.sizeof(0));
		o += state.peerTo(memory, offset + o, State.sizeof(state.getHeaderCount()));
		o += super.peer(memory, offset + o, header.caplen());

		return o;
	}

	public int transferFrom(byte[] buffer) {

		Malloced b = getMemoryBuffer(buffer);

		return peer(b, 0);
	}

	public int transferFrom(ByteBuffer buffer) {
		final int len = buffer.limit() - buffer.position();
		Malloced b = getMemoryBuffer(len);

		b.transferFrom(buffer);

		return peer(b, 0);
	}

	public int transferFrom(PcapPacket packet) {
		return packet.transferTo(this);
	}

	public int transferTo(ByteBuffer buffer) {
		int o = header.transferTo(buffer);
		o += state.transferTo(buffer);
		o += super.transferTo(buffer);

		return o;
	}

	public int transferTo(JBuffer buffer) {
		return transferTo(buffer, 0);
	}

	public int transferTo(byte[] buffer) {
		int o = header.transferTo(buffer, 0);
		o += state.transferTo(buffer, o);
		o += super.transferTo(buffer, 0, size(), o);

		return o;
	}

	public int transferTo(JBuffer buffer, int offset) {
		int o = header.transferTo(buffer, offset);
		o += state.transferTo(buffer, 0, state.size(), offset + o);
		o += super.transferTo(buffer, 0, size(), offset + o);

		return o;
	}

	public int transferTo(PcapPacket packet) {
		Malloced buffer = packet.getMemoryBuffer(this.getTotalSize());

		int o = header.transferTo(buffer, 0);
		packet.header.peerTo(buffer, 0);

		packet.state.peerTo(buffer, o, state.size());
		o += state.transferTo(packet.state);

		packet.peer(this, 0, size());
		o += this.transferTo(buffer, 0, size(), o);

		return o;
	}
}
