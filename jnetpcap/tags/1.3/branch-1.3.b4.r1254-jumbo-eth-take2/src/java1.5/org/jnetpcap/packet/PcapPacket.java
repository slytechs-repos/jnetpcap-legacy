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
package org.jnetpcap.packet;

import java.nio.ByteBuffer;

import org.jnetpcap.IncompatiblePeer;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemoryPool;

// TODO: Auto-generated Javadoc
/**
 * The Class PcapPacket.
 */
public class PcapPacket
    extends
    JPacket {

	/** The Constant STATE_SIZE. */
	private final static int STATE_SIZE =
	    PcapHeader.sizeof() + JPacket.State.sizeof(DEFAULT_STATE_HEADER_COUNT);
	
	/**
	 * 
	 */
	static {
		try {
			initIds();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Inits the ids.
	 */
	private native static void initIds();

	/** The header. */
	private final PcapHeader header = new PcapHeader(Type.POINTER);

	/**
	 * Instantiates a new pcap packet.
	 * 
	 * @param buffer
	 *          the buffer
	 */
	public PcapPacket(byte[] buffer) {
		super(Type.POINTER);

		transferStateAndDataFrom(buffer);
	}

	/**
	 * Instantiates a new pcap packet.
	 * 
	 * @param buffer
	 *          the buffer
	 */
	public PcapPacket(ByteBuffer buffer) {
		super(Type.POINTER);

		transferStateAndDataFrom(buffer);
	}

	/**
	 * Instantiates a new pcap packet.
	 * 
	 * @param size
	 *          the size
	 */
	public PcapPacket(int size) {
		super(size, STATE_SIZE);
	}

	/**
	 * Instantiates a new pcap packet.
	 * 
	 * @param size
	 *          the size
	 * @param headerCount
	 *          the header count
	 */
	public PcapPacket(int size, int headerCount) {
		super(size, PcapHeader.sizeof() + JPacket.State.sizeof(headerCount));
	}

	/**
	 * Instantiates a new pcap packet.
	 * 
	 * @param buffer
	 *          the buffer
	 */
	public PcapPacket(JBuffer buffer) {
		super(Type.POINTER);

		transferStateAndDataFrom(buffer);
	}

	/**
	 * Instantiates a new pcap packet.
	 * 
	 * @param src
	 *          the src
	 */
	public PcapPacket(JPacket src) {
		super(Type.POINTER);

		if (src instanceof PcapPacket) {
			((PcapPacket) src).transferStateAndDataTo(this);
		} else {
			throw new UnsupportedOperationException(
			    "Unsupported packet type for this constructor");
		}
	}

	/**
	 * Instantiates a new pcap packet.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 */
	public PcapPacket(PcapHeader header, ByteBuffer buffer) {
		super(Type.POINTER);

		transferHeaderAndDataFrom0(header, buffer);
	}

	/**
	 * Instantiates a new pcap packet.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 */
	public PcapPacket(PcapHeader header, JBuffer buffer) {
		super(Type.POINTER);

		transferHeaderAndDataFrom0(header, buffer);
	}

	/**
	 * Instantiates a new pcap packet.
	 * 
	 * @param src
	 *          the src
	 */
	public PcapPacket(PcapPacket src) {
		super(Type.POINTER);

		src.transferStateAndDataTo(this);
	}

	/**
	 * Instantiates a new pcap packet.
	 * 
	 * @param type
	 *          the type
	 */
	public PcapPacket(Type type) {
		super(type);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JPacket#getCaptureHeader()
	 */
	@Override
	public PcapHeader getCaptureHeader() {
		return header;
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JPacket#getTotalSize()
	 */
	public int getTotalSize() {
		return super.size() + state.size() + header.size();
	}

	/**
	 * Peer header and data.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int peerHeaderAndData(JBuffer buffer) {
		int o = header.peer(buffer, 0);
		o += super.peer(buffer, o, buffer.size() - header.size());

		return o;
	}
	
	/**
	 * Peer.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int peer(PcapHeader header, JBuffer buffer) {
		int o = this.header.peerTo(header, 0);
		o += this.peer(buffer);
		
		return o;
	}

	/**
	 * Peer and scan.
	 * 
	 * @param dlt
	 *          the dlt
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int peerAndScan(int dlt, PcapHeader header, JBuffer buffer) {
		int o = this.header.peerTo(header, 0);
		o += this.peer(buffer);

		scan(dlt);

		return o;
	}

	/**
	 * Peer header and data.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 * @throws PeeringException
	 *           the peering exception
	 */
	public int peerHeaderAndData(PcapHeader header, ByteBuffer buffer)
			throws PeeringException {
		int o = this.header.peerTo(header, 0);
		o += super.peer(buffer);

		return o;
	}

	/**
	 * Peer header and data.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int peerHeaderAndData(PcapHeader header, JBuffer buffer) {
		int o = this.header.peerTo(header, 0);
		o += super.peer(buffer);

		return o;
	}

	/**
	 * Peer state and data.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 * @throws PeeringException
	 *           the peering exception
	 */
	public int peerStateAndData(ByteBuffer buffer) throws PeeringException {
		if (buffer.isDirect() == false) {
			throw new PeeringException("unable to peer a non-direct ByteBuffer");
		}
		return peerStateAndData(getMemoryBuffer(buffer), 0);
	}

	/**
	 * Peer state and data.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int peerStateAndData(JBuffer buffer) {
		return peerStateAndData(getMemoryBuffer(buffer), 0);
	}

	/**
	 * Peer state and data.
	 * 
	 * @param memory
	 *          the memory
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	private int peerStateAndData(JBuffer memory, int offset) {

		int o = header.peer(memory, offset);
		state.peerTo(memory, offset + o, State.sizeof(0));
		o += state.peerTo(memory, offset + o, State.sizeof(state.getHeaderCount()));
		o += super.peer(memory, offset + o, header.caplen());

		return o;
	}

	/**
	 * Transfer header and data from.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferHeaderAndDataFrom(PcapHeader header, ByteBuffer buffer) {
		return transferHeaderAndDataFrom0(header, buffer);
	}

	/**
	 * Transfer header and data from0.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	private int transferHeaderAndDataFrom0(PcapHeader header, ByteBuffer buffer) {
		return getMemoryPool().duplicate2(header, buffer, this.header, this);
	}

	/**
	 * Transfer header and data from.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferHeaderAndDataFrom(PcapHeader header, JBuffer buffer) {
		return transferHeaderAndDataFrom0(header, buffer);
	}

	/**
	 * Transfer header and data from0.
	 * 
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	private int transferHeaderAndDataFrom0(PcapHeader header, JBuffer buffer) {
		return getMemoryPool().duplicate2(header, buffer, this.header, this);
	}

	/**
	 * Transfer state and data from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferStateAndDataFrom(byte[] buffer) {

		JBuffer b = getMemoryBuffer(buffer);

		return peerStateAndData(b, 0);
	}

	/**
	 * Transfer state and data from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferStateAndDataFrom(ByteBuffer buffer) {
		final int len = buffer.limit() - buffer.position();
		JBuffer b = getMemoryBuffer(len);

		b.transferFrom(buffer, 0);

		return peerStateAndData(b, 0);
	}

	/**
	 * Transfer state and data from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferStateAndDataFrom(JBuffer buffer) {
		final int len = buffer.size();
		JBuffer b = getMemoryBuffer(len);

		buffer.transferTo(b);

		return peerStateAndData(b, 0);
	}

	/**
	 * Transfer state and data from.
	 * 
	 * @param packet
	 *          the packet
	 * @return the int
	 */
	public int transferStateAndDataFrom(PcapPacket packet) {
		return packet.transferStateAndDataTo(this);
	}

	/**
	 * Transfer state and data to.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferStateAndDataTo(byte[] buffer) {
		int o = header.transferTo(buffer, 0);
		o += state.transferTo(buffer, o);
		o += super.transferTo(buffer, 0, size(), o);

		return o;
	}

	/**
	 * Transfer state and data to.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferStateAndDataTo(ByteBuffer buffer) {
		int o = header.transferTo(buffer);
		o += state.transferTo(buffer);
		o += super.transferTo(buffer);

		return o;
	}

	/**
	 * Transfer state and data to.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferStateAndDataTo(JBuffer buffer) {
		return transferStateAndDataTo(buffer, 0);
	}

	/**
	 * Transfer state and data to.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int transferStateAndDataTo(JBuffer buffer, int offset) {
		int o = header.transferTo(buffer, offset);
		o += state.transferTo(buffer, 0, state.size(), offset + o);
		o += super.transferTo(buffer, 0, size(), offset + o);

		return o;
	}

	/**
	 * Transfer state and data to.
	 * 
	 * @param packet
	 *          the packet
	 * @return the int
	 */
	public int transferStateAndDataTo(PcapPacket packet) {
		JBuffer buffer = packet.getMemoryBuffer(this.getTotalSize());

		int o = header.transferTo(buffer, 0);
		packet.header.peerTo(buffer, 0);

		packet.state.peerTo(buffer, o, state.size());
		o += state.transferTo(packet.state);

		packet.peer(buffer, o, size());
		o += this.transferTo(buffer, 0, size(), o);

		return o;
	}
}
