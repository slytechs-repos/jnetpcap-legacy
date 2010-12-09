/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.winpcap;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapPktHdr;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.packet.PeeringException;

// TODO: Auto-generated Javadoc
/**
 * The Class WinPcapSendQueue.
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
@SuppressWarnings("deprecation")
public class WinPcapSendQueue extends JStruct {
	
	/** The Constant DEFAULT_QUEUE_SIZE. */
	public final static int DEFAULT_QUEUE_SIZE = 64 * 1024;

	/** The Constant STRUCT_NAME. */
	public final static String STRUCT_NAME = "pcap_send_queue";

	/**
	 * Sizeof.
	 * 
	 * @return the int
	 */
	public native static int sizeof();

	/** The buffer. */
	private JBuffer buffer;

	/**
	 * Instantiates a new win pcap send queue.
	 */
	public WinPcapSendQueue() {
		this(DEFAULT_QUEUE_SIZE);
	}

	/**
	 * Instantiates a new win pcap send queue.
	 * 
	 * @param data
	 *          the data
	 */
	public WinPcapSendQueue(byte[] data) {
		super(STRUCT_NAME, sizeof());

		this.buffer = new JBuffer(data.length); 
		this.buffer.order(ByteOrder.nativeOrder()); // Force byte ordering

		this.buffer.setByteArray(0, data);
		setMaxLen(data.length);
	}
	
	/**
	 * Instantiates a new win pcap send queue.
	 * 
	 * @param buffer
	 *          the buffer
	 * @throws PeeringException
	 *           the peering exception
	 */
	public WinPcapSendQueue(ByteBuffer buffer) throws PeeringException {
		super(STRUCT_NAME, sizeof());
		this.buffer = new JBuffer(Type.POINTER);
		this.buffer.order(ByteOrder.nativeOrder()); // Force byte ordering

		if (buffer.isDirect() == false) {
			throw new IllegalArgumentException("Only direct buffers are accepted. "
			    + "See ByteBuffer.allocateDirect method.");
		}
		this.buffer.peer(buffer);
		setMaxLen(this.buffer.size());
	}
	
	/**
	 * Instantiates a new win pcap send queue.
	 * 
	 * @param size
	 *          the size
	 */
	public WinPcapSendQueue(int size) {
		super(STRUCT_NAME, sizeof());
		this.buffer = new JBuffer(size);
		this.buffer.order(ByteOrder.nativeOrder()); // Force byte ordering
		
		setMaxLen(size);
		setBuffer(buffer);
	}



	/**
	 * Gets the buffer.
	 * 
	 * @return the buffer
	 */
	public JBuffer getBuffer() {
		return buffer;
	}
	
	/**
	 * Gets the len.
	 * 
	 * @return the len
	 */
	public native int getLen();

	/**
	 * Gets the max len.
	 * 
	 * @return the max len
	 */
	public native int getMaxLen();

	/**
	 * Inc len.
	 * 
	 * @param delta
	 *          the delta
	 * @return the int
	 */
	public native int incLen(int delta);
	
	/**
	 * Queue.
	 * 
	 * @param header
	 *          the header
	 * @param data
	 *          the data
	 * @return the int
	 */
	public int queue(PcapHeader header, byte[] data) {
		return queue(header, new JBuffer(data));
	}

	/**
	 * Queue.
	 * 
	 * @param header
	 *          the header
	 * @param data
	 *          the data
	 * @return the int
	 */
	public int queue(PcapHeader header, ByteBuffer data) {
		return queue(header, new JBuffer(data));
	}
	
	/**
	 * Queue.
	 * 
	 * @param header
	 *          the header
	 * @param data
	 *          the data
	 * @return the int
	 */
	public int queue(PcapHeader header, JBuffer data) {
		
		header.transferTo(buffer, 0, header.size(), getLen());
		setLen(getLen() + header.size());
		
		data.transferTo(buffer, 0, data.size(), getLen());
		setLen(getLen() + data.size());
		
		return Pcap.OK;
	}
	
	/**
	 * Queue.
	 * 
	 * @param hdr
	 *          the hdr
	 * @param data
	 *          the data
	 * @return the int
	 */
	public int queue(PcapPktHdr hdr, byte[] data) {

		if (data.length != hdr.getCaplen()) {
			throw new IllegalArgumentException("Buffer length "
			    + "does not equal length in packet header");
		}

		int p = getLen();

		/*
		 * Write the packet header first
		 */
		buffer.setInt(p, (int) hdr.getSeconds());
		buffer.setInt(p + 4, (int) hdr.getUseconds());
		buffer.setInt(p + 8, (int) hdr.getCaplen());
		buffer.setInt(p + 12, (int) hdr.getLen());

		buffer.setByteArray(p + 16, data);
		incLen(16 + data.length);

		return 0;
	}
	
	/**
	 * Queue.
	 * 
	 * @param hdr
	 *          the hdr
	 * @param data
	 *          the data
	 * @return the int
	 */
	public int queue(PcapPktHdr hdr, ByteBuffer data) {

		int length = data.limit() - data.position();
		if (length != hdr.getCaplen()) {
			throw new IllegalArgumentException("Buffer length (limit - position) "
			    + "does not equal length in packet header");
		}

		
		int p = getLen();

		/*
		 * Write the packet header first
		 */
		buffer.setInt(p, (int) hdr.getSeconds());
		buffer.setInt(p + 4, (int) hdr.getUseconds());
		buffer.setInt(p + 8, (int) hdr.getCaplen());
		buffer.setInt(p + 12, (int) hdr.getLen());

		buffer.setByteBuffer(p + 16, data);
		incLen(16 + length);

		return 0;
	}
	
	/**
	 * Sets the buffer.
	 * 
	 * @param buffer
	 *          the new buffer
	 */
	private native void setBuffer(JBuffer buffer);

	/**
	 * Sets the len.
	 * 
	 * @param len
	 *          the new len
	 */
	public native void setLen(int len);

	/**
	 * Sets the max len.
	 * 
	 * @param len
	 *          the new max len
	 */
	public native void setMaxLen(int len);
}
