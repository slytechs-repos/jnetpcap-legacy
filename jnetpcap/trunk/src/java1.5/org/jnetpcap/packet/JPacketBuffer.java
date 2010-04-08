package org.jnetpcap.packet;

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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Iterator;

import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;

/**
 * A memory buffer used to hold multiple packets. This specialized buffer is
 * filled by jNetPcap with multiple raw packet data and capture headers upto the
 * specified size of the buffer. The packets can then be accessed via accessor
 * methods. The structure of the data within the buffer is as follows:
 * 
 * <pre>
 * [count][capture header 1][packet data 1][capture header n][packet data n]
 * </pre>
 * 
 * <p>
 * </p>
 * 
 * @see org.jnetpcap.Pcap#loop(int, JPacketBufferHandler, Object)
 * @see org.jnetpcap.Pcap#dispatch(int, int, JPacketBufferHandler, Object)
 * @see JPacketBufferHandler
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JPacketBuffer
    extends
    JBuffer implements Iterable<JPacket> {

	/**
	 * Size of the static header found at the front of the buffer that describes
	 * the contents of this buffer.
	 */
	public final static int HEADER_SIZE = 64;

	/**
	 * Create a buffer of specified size.
	 * 
	 * @param size
	 *          length of the buffer in octets
	 */
	public JPacketBuffer(int size) {
		super(size);

		super.order(ByteOrder.nativeOrder());
	}

	/**
	 * Creates a buffer object and peers it with the data contained in the
	 * supplied buffer.
	 * 
	 * @param peer
	 *          buffer to peer with
	 */
	public JPacketBuffer(ByteBuffer peer) {
		super(peer);
		super.order(ByteOrder.nativeOrder());
	}

	/**
	 * Create a buffer object and peers it with the data contained in the supplied
	 * buffer.
	 * 
	 * @param peer
	 *          buffer to peer with
	 */
	public JPacketBuffer(JBuffer peer) {
		super(peer);
	}

	/**
	 * Creates an empty buffer object ready for peering.
	 * 
	 * @param type
	 *          memory model type
	 */
	public JPacketBuffer(Type type) {
		super(type);
		super.order(ByteOrder.nativeOrder());
	}

	/**
	 * Gets the number of packets stored in this buffer. The count indicates how
	 * many pairs of capture header and packet data have been stored within this
	 * buffer.
	 * 
	 * @return number of packets stored in this buffer
	 */
	public int getPacketCount() {
		return super.getInt(0);
	}

	/**
	 * Gets the DLT (numerical data-link-type ID) of the packets within the
	 * buffer.
	 * 
	 * @return packet dlt
	 */
	private int getPacketDlt() {
		return super.getInt(4);
	}

	/**
	 * Iterator which returns complete packets contained in this buffer.
	 * 
	 * @see java.lang.Iterable#iterator()
	 */
	public Iterator<JPacket> iterator() {
		return new Iterator<JPacket>() {

			/*
			 * Number of packet we have to work with in this buffer
			 */
			final int count = getPacketCount();

			/*
			 * Data-link-type of all the packets in this buffer
			 */
			final int dlt = getPacketDlt();

			/*
			 * This iterators current packet index
			 */
			int index = 0;

			/*
			 * We process the next packet at this offset
			 */
			int offset = HEADER_SIZE; // Passed the description structure at the front

			public boolean hasNext() {
				return index < count;
			}

			public JPacket next() {
				index++;

				/*
				 * Create empty (unpeered) java objects
				 */
				final PcapPacket packet = new PcapPacket(JMemory.POINTER);
				final PcapHeader header = packet.getCaptureHeader();

				/*
				 * Peer the header and packet buffer to pcap header and packet data
				 * within the buffer
				 */
				offset += header.peerTo(JPacketBuffer.this, offset);
				offset += packet.peer(JPacketBuffer.this, offset, header.caplen());

				/*
				 * Alignment on 16-bit boundary, strictly enforced at native level as
				 * well.
				 */
				offset += (header.caplen() % 2);

				/*
				 * Decode the packet
				 */
				packet.scan(dlt);

				return packet;
			}

			public void remove() {
				throw new UnsupportedOperationException(
				    "This operation not supported on JPacketBuffer type");
			}
		};
	}

	/**
	 * Gets a debug string of this buffer.
	 * 
	 * @return debug string
	 */
	@Override
	public String toString() {
		return "cnt:dlt=" + getPacketCount() + ":" + getPacketDlt();
	}
}
