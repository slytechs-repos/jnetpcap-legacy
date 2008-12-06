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

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemoryPool.Block.Malloced;
import org.jnetpcap.packet.JPacket.State;
import org.jnetpcap.packet.format.FormatUtils;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JMemoryPacket
    extends JPacket {

	private static class JMemoryHeader implements JCaptureHeader {

		private int caplen;

		private long inMillis;

		private long nanos;

		private long seconds;

		private int wirelen;

		public JMemoryHeader() {
			// Empty
		}

		/**
		 * @param caplen
		 * @param nanos
		 * @param seconds
		 */
		public JMemoryHeader(int caplen, int wirelen, long nanos, long seconds) {
			init(caplen, wirelen, nanos, seconds);
		}

		public int caplen() {
			return caplen;
		}

		public final int getWirelen() {
			return this.wirelen;
		}

		public void init(int caplen, int wirelen, long nanos, long seconds) {
			this.caplen = caplen;
			this.wirelen = wirelen;
			this.nanos = nanos;
			this.seconds = seconds;

			this.inMillis = seconds() * 1000 + nanos() / 1000000;

		}

		public long nanos() {
			return nanos;
		}

		public long seconds() {
			return seconds;
		}

		public final void setWirelen(int wirelen) {
			this.wirelen = wirelen;
		}

		public long timestampInMillis() {
			return inMillis;
		}

		public int wirelen() {
			return wirelen;
		}

	}

	private final JMemoryHeader header = new JMemoryHeader();;

	/**
	 * @param buffer
	 */
	public JMemoryPacket(byte[] buffer) {
		super(Type.POINTER);

		transferStateAndDataFrom(buffer);
	}

	/**
	 * @param buffer
	 * @throws PeeringException
	 */
	public JMemoryPacket(ByteBuffer buffer) throws PeeringException {
		super(Type.POINTER);

		transferStateAndDataFrom(buffer);
	}

	/**
	 * @param size
	 */
	public JMemoryPacket(int size) {
		super(size, State.sizeof(DEFAULT_STATE_HEADER_COUNT));
	}

	/**
	 * Creates a new fully decoded packet from data provides in the buffer. The
	 * buffer contains raw packet data. The packet is peered with the buffer,
	 * allocating new memory if neccessary, and scanned using internal scanner.
	 * 
	 * @param id
	 *          numerical id of first protocol (DLT)
	 * @param buffer
	 *          buffer containing raw packet data
	 */
	public JMemoryPacket(int id, byte[] buffer) {
		super(Type.POINTER);

		final Malloced mem = getMemoryBuffer(buffer);

		super.peer(mem);

		scan(id);
	}

	/**
	 * Creates a new fully decoded packet from the hexdump data provided.
	 * 
	 * @param id
	 *          numerical id of first protocol (DLT)
	 * @param hexdump
	 *          hexdump of the packet contents which will loaded into the raw data
	 *          buffer
	 */
	public JMemoryPacket(int id, String hexdump) {
		this(id, FormatUtils.toByteArray(hexdump));
	}

	/**
	 * @param buffer
	 */
	public JMemoryPacket(JBuffer buffer) {
		super(Type.POINTER);

		transferStateAndDataFrom(buffer);
	}

	/**
	 * @param type
	 */
	public JMemoryPacket(Type type) {
		super(type);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JPacket#getCaptureHeader()
	 */
	@Override
	public JCaptureHeader getCaptureHeader() {
		return this.header;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JPacket#getStateAndMemorySize()
	 */
	@Override
	public int getTotalSize() {
		return super.size() + super.state.size();
	}

	/**
	 * @param memory
	 * @param offset
	 * @return
	 */
	public int peerStateAndData(Malloced memory, int offset) {

		state.peerTo(memory, offset, State.sizeof(0));
		int o = state.peerTo(memory, offset, State.sizeof(state.getHeaderCount()));
		o += super.peer(memory, offset + o, header.caplen());

		return o;
	}

	/**
	 * @param buffer
	 */
	public int transferStateAndDataFrom(byte[] buffer) {
		Malloced b = getMemoryBuffer(buffer);

		return peerStateAndData(b, 0);
	}

	/**
	 * @param buffer
	 */
	public int transferStateAndDataFrom(ByteBuffer buffer) {
		final int len = buffer.limit() - buffer.position();
		Malloced b = getMemoryBuffer(len);

		b.transferFrom(buffer);

		return peerStateAndData(b, 0);
	}

	/**
	 * @param buffer
	 */
	public int transferStateAndDataFrom(JBuffer buffer) {
		final int len = buffer.size();
		Malloced b = getMemoryBuffer(len);

		b.transferFrom(buffer);

		return peerStateAndData(b, 0);
	}

	public int transferStateAndDataTo(JPacket packet, int offset) {
		final Malloced buffer = packet.getMemoryBuffer(this.getTotalSize());

		packet.state.peerTo(buffer, offset, state.size());
		int o = state.transferTo(packet.state);

		packet.peer(this, offset, size());
		o += this.transferTo(buffer, 0, size(), offset + o);

		final JCaptureHeader h = packet.getCaptureHeader();
		header.init(h.caplen(), h.wirelen(), h.seconds(), h.nanos());

		return o;
	}

}
