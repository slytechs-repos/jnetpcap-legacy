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

		final JBuffer mem = getMemoryBuffer(buffer);

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
	 * Peers the contents of the buffer directly with this packet. No copies are
	 * performed but the packet state and data are expected to be contained within
	 * the buffer with a certain layout as described below:
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +-----+----+
	 * |State|Data|
	 * +-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          Buffer containing packet header, state and data. Position property
	 *          specifies that start within the buffer where to peer the first
	 *          byte.
	 * @return number of bytes that were peered out of the buffer
	 * @throws PeeringException
	 *           thrown if ByteBuffer is not direct byte buffer type
	 */
	public int peerStateAndData(ByteBuffer buffer) throws PeeringException {
		if (buffer.isDirect() == false) {
			throw new PeeringException("unable to peer a non-direct ByteBuffer");
		}
		return peerStateAndData(getMemoryBuffer(buffer), 0);
	}

	/**
	 * Peers the contents of the buffer directly with this packet. No copies are
	 * performed but the packet state and data are expected to be contained within
	 * the buffer with a certain layout as described below:
	 * <p>
	 * Supplied buffer layout expected:
	 * 
	 * <pre>
	 * +-----+----+
	 * |State|Data|
	 * +-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing packet header, state and data
	 * @return number of bytes that were peered out of the buffer
	 */
	public int peerStateAndData(JBuffer buffer) {
		return peerStateAndData(getMemoryBuffer(buffer), 0);
	}

	/**
	 * @param memory
	 * @param offset
	 * @return
	 */
	private int peerStateAndData(JBuffer memory, int offset) {

		state.peerTo(memory, offset, State.sizeof(0));
		int o = state.peerTo(memory, offset, State.sizeof(state.getHeaderCount()));
		o += super.peer(memory, offset + o, header.caplen());

		return o;
	}

	/**
	 * @param buffer
	 */
	public int transferStateAndDataFrom(byte[] buffer) {
		JBuffer b = getMemoryBuffer(buffer);

		return peerStateAndData(b, 0);
	}

	/**
	 * @param buffer
	 */
	public int transferStateAndDataFrom(ByteBuffer buffer) {
		final int len = buffer.limit() - buffer.position();
		JBuffer b = getMemoryBuffer(len);

		b.transferFrom(buffer, 0);

		return peerStateAndData(b, 0);
	}

	/**
	 * @param buffer
	 */
	public int transferStateAndDataFrom(JBuffer buffer) {
		final int len = buffer.size();
		JBuffer b = getMemoryBuffer(len);

		b.transferFrom(buffer);

		return peerStateAndData(b, 0);
	}

	public int transferStateAndDataFrom(JMemoryPacket packet) {
		return packet.transferTo(this);
	}

	public int transferStateAndDataFrom(JPacket packet) {
		int len = packet.state.size() + packet.size();
		JBuffer mem = getMemoryBuffer(len);

		int o = packet.state.transferTo(mem, 0, packet.state.size(), 0);
		o += packet.transferTo(mem, 0, packet.size(), o);

		return o;
	}

	/**
	 * Copies contents of this packet to buffer. The packets capture state and
	 * packet data are copied to new buffer. After completion of this operation
	 * the complete contents and state of the packet will be transfered to the
	 * buffer. The layout of the buffer data will be as described below. A buffer
	 * with this type of layout is suitable for any transferStateAndData or peer
	 * methods for any buffers that are JMemory based. The buffer has to be large
	 * enough to hold all of the packet content as returned by method
	 * {@link #getTotalSize()}. If the buffer is too small and a runtime
	 * exception may be thrown.
	 * <p>
	 * The buffer layout will look like the following:
	 * 
	 * <pre>
	 * +-----+----+
	 * |State|Data|
	 * +-----+----+
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @param buffer
	 *          buffer containing capture header, packet state and data buffer
	 *          sequentially in the buffer
	 * @return number of bytes copied
	 */
	public int transferStateAndDataTo(JBuffer buffer, int offset) {
		int o = state.transferTo(buffer, 0, state.size(), offset);
		o += super.transferTo(buffer, 0, size(), offset + o);

		return o;
	}

	public int transferStateAndDataTo(JMemoryPacket packet) {
		final JBuffer buffer = packet.getMemoryBuffer(this.getTotalSize());

		packet.transferStateAndDataTo(buffer, 0);

		return peerStateAndData(buffer, 0);
	}
}
