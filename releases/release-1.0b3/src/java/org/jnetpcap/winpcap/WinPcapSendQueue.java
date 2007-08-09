package org.jnetpcap.winpcap;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.PcapPktHdr;

/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
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

/**
 * Class peered with native <code>pcap_send_queue</code> structure. A queue
 * of raw packets that will be sent to the network with
 * <code>WinPcap.sendqueueTransmit()</code>. The class peers with native C
 * pcap_send_queue structure and allows direct control. The structure can be
 * allocated using WinPcap.sendQueueAlloc method or can be directly instantiated
 * using one o the public constructors.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class WinPcapSendQueue {

	/**
	 * Constant used to determine the default queue size which is 64Kb (1024 *
	 * 64).
	 */
	public final static int DEFAULT_QUEUE_SIZE = 64 * 1024;

	private ByteBuffer buffer;

	/**
	 * Allocates default size buffer for use as a send queue.
	 */
	public WinPcapSendQueue() {
		this(DEFAULT_QUEUE_SIZE);
	}

	/**
	 * Allocates specific queue <code>size</code>
	 * 
	 * @param size
	 *          size of the queue in bytes
	 */
	public WinPcapSendQueue(int size) {
		this.buffer = ByteBuffer.allocateDirect(DEFAULT_QUEUE_SIZE);
		this.buffer.flip();
		this.buffer.order(ByteOrder.nativeOrder()); // Force byte ordering
	}

	/**
	 * <p>
	 * The queue uses the supplied byte buffer which holds the buffers contents.
	 * The buffer must a direct buffer, array based buffers will be rejected and
	 * an exception thrown. The properties of the buffer are used as follows. The
	 * start of the buffer is always with index 0, and end of queue content at
	 * current buffer's limit property (comparible to pcap_send_queue.len). The
	 * capacity property (comparible to pcap_send_queue.maxlen) determines maximum
	 * amount of data that can be further stored in the buffer.
	 * </p>
	 * <p>
	 * Note that changing properties of the buffer after creating this queue
	 * object, will have immediate effect up on the queue. You do not have to use
	 * the queue's provided methods to change the limit property. This should
	 * allow of external addition of the
	 * </p>
	 * 
	 * @param buffer
	 *          a direct buffer containing the data to be send
	 */
	public WinPcapSendQueue(ByteBuffer buffer) {
		this.buffer = buffer;

		if (buffer.isDirect() == false) {
			throw new IllegalArgumentException("Only direct buffers are accepted. "
			    + "See ByteBuffer.allocateDirect method.");
		}

		this.buffer = buffer;
		this.buffer.order(ByteOrder.nativeOrder()); // Force byte ordering
	}

	/**
	 * Creates a sendqueue by allocating a buffer to hold the supplied data. The
	 * data array is copied into the buffer.
	 * 
	 * @param data
	 *          data to be copied into the queue
	 */
	public WinPcapSendQueue(byte[] data) {

		this.buffer = ByteBuffer.allocateDirect(data.length);

		buffer.put(data);
		buffer.flip();
	}

	/**
	 * Sets the peered <code>pcap_send_queue.len</code> field which specifies
	 * the urrent size of the queue, in bytes.
	 * 
	 * @param len
	 *          current size of the queue, in bytes
	 */
	public void setLen(int len) {
		buffer.limit(len);
	}

	/**
	 * Gets the current size of the queue, in bytes.
	 * 
	 * @return current size of the queue, in bytes
	 */
	public int getLen() {
		return buffer.limit();
	}

	/**
	 * Gets the maximum size of the the queue, in bytes. This variable contains
	 * the size of the buffer field.
	 * 
	 * @return maximum size of the the queue, in bytes
	 */
	public int getMaxLen() {
		return buffer.capacity();
	}

	/**
	 * Gets the buffer containing the packets to be sent.
	 * 
	 * @return buffer containing the packets to be sent
	 */
	public ByteBuffer getBuffer() {
		return this.buffer;
	}

	/**
	 * Add a packet to a send queue. This method adds a packet at the end of the
	 * send queue pointed by the queue parameter. <code>hdr</code> points to a
	 * PcapPktHdr structure with the timestamp and the length of the packet, data
	 * points to a buffer with the data of the packet. The PcapPktHdr structure is
	 * the same used by WinPcap and libpcap to store the packets in a file,
	 * therefore sending a capture file is straightforward. 'Raw packet' means
	 * that the sending application will have to include the protocol headers,
	 * since every packet is sent to the network 'as is'. The CRC of the packets
	 * needs not to be calculated, because it will be transparently added by the
	 * network interface.
	 * 
	 * @param hdr
	 *          all fields need to be initialized as they are all used
	 * @param data
	 *          Buffer containing packet data. The buffer's position and limit
	 *          properties determine the area of the buffer to be copied into the
	 *          queue. The length of the data must much what is in the header.
	 *          Also the queue has to be large enough to hold all of the data, or
	 *          an exception will be thrown.
	 * @return 0 on success; exception thrown on failure
	 * @throws IllegalArgumentException
	 *           if amount of data in the buffer (limit - position) does match the
	 *           hdr.getCaplen() value
	 * @throws BufferUnderflowException
	 *           if the queues buffer capacity is too small to hold all of the
	 *           data
	 */
	public int queue(PcapPktHdr hdr, ByteBuffer data) {

		if (data.limit() - data.position() != hdr.getCaplen()) {
			throw new IllegalArgumentException("Buffer length (limit - position) "
			    + "does not equal length in packet header");
		}

		int length = data.limit() - data.position();

		/*
		 * Advance the limit to make room for our data
		 */
		buffer.limit(buffer.limit() + length + 4 * 4);

		/*
		 * Write the packet header first
		 */
		buffer.putInt((int) hdr.getSeconds());
		buffer.putInt((int) hdr.getUseconds());
		buffer.putInt((int) hdr.getCaplen());
		buffer.putInt((int) hdr.getLen());

		buffer.put(data);

		return 0;
	}

	/**
	 * Add a packet to a send queue. This method adds a packet at the end of the
	 * send queue pointed by the queue parameter. <code>hdr</code> points to a
	 * PcapPktHdr structure with the timestamp and the length of the packet, data
	 * points to a buffer with the data of the packet. The PcapPktHdr structure is
	 * the same used by WinPcap and libpcap to store the packets in a file,
	 * therefore sending a capture file is straightforward. 'Raw packet' means
	 * that the sending application will have to include the protocol headers,
	 * since every packet is sent to the network 'as is'. The CRC of the packets
	 * needs not to be calculated, because it will be transparently added by the
	 * network interface.
	 * 
	 * @param hdr
	 *          all fields need to be initialized as they are all used
	 * @param data
	 *          Buffer containing packet data. The length of the data must much
	 *          what is in the header. Also the queue has to be large enough to
	 *          hold all of the data, or an exception will be thrown.
	 * @return 0 on success; exception thrown on failure
	 * @throws IllegalArgumentException
	 *           if amount of data does match the hdr.getCaplen() value
	 * @throws BufferUnderflowException
	 *           if the queues buffer capacity is too small to hold all of the
	 *           data
	 */
	public int queue(PcapPktHdr hdr, byte[] data) {

		if (data.length != hdr.getCaplen()) {
			throw new IllegalArgumentException("Buffer length "
			    + "does not equal length in packet header");
		}

		/*
		 * Write the packet header first
		 */
		buffer.limit(buffer.limit() + data.length + 4 * 4);
		buffer.putInt((int) hdr.getSeconds());
		buffer.putInt((int) hdr.getUseconds());
		buffer.putInt((int) hdr.getCaplen());
		buffer.putInt((int) hdr.getLen());

		buffer.put(data);

		return 0;
	}
}
