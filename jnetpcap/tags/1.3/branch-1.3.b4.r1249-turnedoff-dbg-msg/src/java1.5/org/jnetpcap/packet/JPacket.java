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

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JMemoryPool;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;

// TODO: Auto-generated Javadoc
/**
 * The Class JPacket.
 */
public abstract class JPacket extends JBuffer implements JHeaderAccessor {

	/**
	 * The Class State.
	 */
	public static class State extends JStruct {

		/** The Constant FLAG_TRUNCATED. */
		public final static int FLAG_TRUNCATED = 0x01;

		/** The Constant STRUCT_NAME. */
		public final static String STRUCT_NAME = "packet_state_t";

		/**
		 * Sizeof.
		 * 
		 * @param count
		 *          the count
		 * @return the int
		 */
		public static native int sizeof(int count);

		/** The flow key. */
		private final JFlowKey flowKey = new JFlowKey();

		/**
		 * Instantiates a new state.
		 * 
		 * @param size
		 *          the size
		 */
		public State(int size) {
			super(STRUCT_NAME, size);
		}

		/**
		 * Instantiates a new state.
		 * 
		 * @param type
		 *          the type
		 */
		public State(Type type) {
			super(STRUCT_NAME, type);
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.nio.JMemory#cleanup()
		 */
		public void cleanup() {
			super.cleanup();
		}

		/**
		 * Find header index.
		 * 
		 * @param id
		 *          the id
		 * @return the int
		 */
		public int findHeaderIndex(int id) {
			return findHeaderIndex(id, 0);
		}

		/**
		 * Find header index.
		 * 
		 * @param id
		 *          the id
		 * @param instance
		 *          the instance
		 * @return the int
		 */
		public native int findHeaderIndex(int id, int instance);

		/**
		 * Gets the 64 bit header map.
		 * 
		 * @param index
		 *          the index
		 * @return the 64 bit header map
		 */
		public native long get64BitHeaderMap(int index);

		/**
		 * Gets the flags.
		 * 
		 * @return the flags
		 */
		public native int getFlags();

		/**
		 * Gets the flow key.
		 * 
		 * @return the flow key
		 */
		public JFlowKey getFlowKey() {
			return this.flowKey;
		}

		/**
		 * Gets the frame number.
		 * 
		 * @return the frame number
		 */
		public native long getFrameNumber();

		/**
		 * Gets the header count.
		 * 
		 * @return the header count
		 */
		public native int getHeaderCount();

		/**
		 * Gets the header id by index.
		 * 
		 * @param index
		 *          the index
		 * @return the header id by index
		 */
		public native int getHeaderIdByIndex(int index);

		/**
		 * Gets the header length by index.
		 * 
		 * @param index
		 *          the index
		 * @return the header length by index
		 */
		public native int getHeaderLengthByIndex(int index);

		/**
		 * Gets the header offset by index.
		 * 
		 * @param index
		 *          the index
		 * @return the header offset by index
		 */
		public native int getHeaderOffsetByIndex(int index);

		/**
		 * Gets the instance count.
		 * 
		 * @param id
		 *          the id
		 * @return the instance count
		 */
		public native int getInstanceCount(int id);

		/**
		 * Gets the wirelen.
		 * 
		 * @return the wirelen
		 */
		public native int getWirelen();

		/* (non-Javadoc)
		 * @see org.jnetpcap.nio.JMemory#peer(java.nio.ByteBuffer)
		 */
		public int peer(ByteBuffer peer) throws PeeringException {
			int r = super.peer(peer);
			flowKey.peer(this);
			return r;
		}

		/**
		 * Peer.
		 * 
		 * @param peer
		 *          the peer
		 * @return the int
		 */
		public int peer(JBuffer peer) {
			int r = super.peer(peer, 0, size());

			flowKey.peer(this);
			return r;
		}

		/**
		 * Peer.
		 * 
		 * @param peer
		 *          the peer
		 * @param offset
		 *          the offset
		 * @param length
		 *          the length
		 * @return the int
		 * @throws IndexOutOfBoundsException
		 *           the index out of bounds exception
		 */
		public int peer(JBuffer peer, int offset, int length)
				throws IndexOutOfBoundsException {
			int r = super.peer(peer, offset, length);

			flowKey.peer(this);
			return r;
		}

		/**
		 * Peer.
		 * 
		 * @param memory
		 *          the memory
		 * @param offset
		 *          the offset
		 * @return the int
		 */
		public int peer(JMemory memory, int offset) {
			int r = super.peer(memory, offset, size());

			flowKey.peer(this);
			return r;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JPeerable#peer(org.jnetpcap.nio.JMemoryPool.Block,
		 * int, int)
		 */
		/**
		 * Peer.
		 * 
		 * @param peer
		 *          the peer
		 * @param offset
		 *          the offset
		 * @param length
		 *          the length
		 * @return the int
		 * @throws IndexOutOfBoundsException
		 *           the index out of bounds exception
		 */
		public int peer(JMemoryPool.Block peer, int offset, int length)
				throws IndexOutOfBoundsException {
			int r = super.peer(peer, offset, length);

			flowKey.peer(this);
			return r;
		}

		/**
		 * Peer.
		 * 
		 * @param peer
		 *          the peer
		 * @return the int
		 */
		public int peer(State peer) {
			int r = super.peer(peer, 0, size());

			flowKey.peer(this);
			return r;
		}

		/**
		 * Peer header by id.
		 * 
		 * @param id
		 *          the id
		 * @param instance
		 *          the instance
		 * @param dst
		 *          the dst
		 * @return the int
		 */
		public native int peerHeaderById(int id, int instance, JHeader.State dst);

		/**
		 * Peer header by index.
		 * 
		 * @param index
		 *          the index
		 * @param dst
		 *          the dst
		 * @return the int
		 * @throws IndexOutOfBoundsException
		 *           the index out of bounds exception
		 */
		public native int peerHeaderByIndex(int index, JHeader.State dst)
				throws IndexOutOfBoundsException;

		/**
		 * Peer to.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the int
		 */
		public int peerTo(JBuffer buffer, int offset) {
			int r = super.peer(buffer, offset, size());

			flowKey.peer(this);
			return r;
		}

		/**
		 * Peer to.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @param size
		 *          the size
		 * @return the int
		 */
		public int peerTo(JBuffer buffer, int offset, int size) {
			int r = super.peer(buffer, offset, size);

			flowKey.peer(this);
			return r;
		}

		/**
		 * Peer to.
		 * 
		 * @param state
		 *          the state
		 * @param offset
		 *          the offset
		 * @return the int
		 */
		public int peerTo(State state, int offset) {
			int r = super.peer(state, offset, state.size());

			flowKey.peer(this);
			return r;
		}

		/**
		 * Sets the flags.
		 * 
		 * @param flags
		 *          the new flags
		 */
		public native void setFlags(int flags);

		/**
		 * Sets the wirelen.
		 * 
		 * @param length
		 *          the new wirelen
		 */
		public native void setWirelen(int length);

		/* (non-Javadoc)
		 * @see org.jnetpcap.nio.JMemory#toDebugString()
		 */
		public String toDebugString() {

			return super.toDebugString() + "\n" + toDebugStringJPacketState();
		}

		/**
		 * To debug string j packet state.
		 * 
		 * @return the string
		 */
		private native String toDebugStringJPacketState();

		/**
		 * Transfer to.
		 * 
		 * @param dst
		 *          the dst
		 * @param dstOffset
		 *          the dst offset
		 * @return the int
		 */
		public int transferTo(byte[] dst, int dstOffset) {
			return super.transferTo(dst, 0, size(), dstOffset);
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.nio.JMemory#transferTo(byte[], int, int, int)
		 */
		public int transferTo(byte[] dst, int srcOffset, int length, int dstOffset) {
			return super.transferTo(dst, srcOffset, size(), dstOffset);
		}

		/* (non-Javadoc)
		 * @see org.jnetpcap.nio.JMemory#transferTo(org.jnetpcap.nio.JBuffer, int, int, int)
		 */
		public int transferTo(JBuffer dst, int srcOffset, int length, int dstOffset) {
			return super.transferTo(dst, srcOffset, size(), dstOffset);
		}

		/**
		 * Transfer to.
		 * 
		 * @param dst
		 *          the dst
		 * @return the int
		 */
		public int transferTo(State dst) {
			return super.transferTo(dst, 0, size(), 0);
		}
	}

	/** The Constant DEFAULT_STATE_HEADER_COUNT. */
	public final static int DEFAULT_STATE_HEADER_COUNT = 20;

	/** The default scanner. */
	protected static JScanner defaultScanner;

	/** The out. */
	private static JFormatter out = new TextFormatter(new StringBuilder());

	/** The pool. */
	protected static JMemoryPool pool = new JMemoryPool();

	/**
	 * Gets the default scanner used to scan a packet per user request.
	 * 
	 * @return the default scanner used to scan a packet per user request
	 */
	public static JScanner getDefaultScanner() {
		if (defaultScanner == null) {
			synchronized (JScanner.class) {
				if (defaultScanner == null) {
					defaultScanner = new JScanner();
				}
			}
		}
		return defaultScanner;
	}
	
	/**
	 * Shutdown.
	 */
	public static void shutdown() {
		defaultScanner = null;
		pool = null;
	}

	/**
	 * Gets the formatter.
	 * 
	 * @return the formatter
	 */
	public static JFormatter getFormatter() {
		return JPacket.out;
	}

	/**
	 * Gets the memory pool.
	 * 
	 * @return the memory pool
	 */
	public static JMemoryPool getMemoryPool() {
		return pool;
	}

	/**
	 * Sets the formatter.
	 * 
	 * @param out
	 *          the new formatter
	 */
	public static void setFormatter(JFormatter out) {
		JPacket.out = out;
	}

	/**
	 * Sets the memory pool.
	 * 
	 * @param pool
	 *          the new memory pool
	 */
	public static void setMemoryPool(JMemoryPool pool) {
		JPacket.pool = pool;
	}

	/** The memory. */
	protected final JBuffer memory = new JBuffer(Type.POINTER);

	/** The state. */
	protected final State state = new State(Type.POINTER);

	/**
	 * Instantiates a new j packet.
	 * 
	 * @param size
	 *          the size
	 * @param state
	 *          the state
	 */
	public JPacket(int size, int state) {
		super(Type.POINTER);

		allocate(size + state);
	}

	/**
	 * Instantiates a new j packet.
	 * 
	 * @param type
	 *          the type
	 */
	public JPacket(Type type) {
		super(type);
	}

	/**
	 * Allocate.
	 * 
	 * @param size
	 *          the size
	 */
	public void allocate(int size) {
		pool.allocate(size, memory);
	}

	/**
	 * Gets the allocated memory size.
	 * 
	 * @return the allocated memory size
	 */
	public int getAllocatedMemorySize() {
		if (!memory.isInitialized()) {
			return 0;
		}

		return memory.size();
	}

	/**
	 * Gets the capture header.
	 * 
	 * @return the capture header
	 */
	public abstract JCaptureHeader getCaptureHeader();

	/**
	 * Gets the frame number.
	 * 
	 * @return the frame number
	 */
	public long getFrameNumber() {
		return state.getFrameNumber() + 1;
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderAccessor#getHeader(org.jnetpcap.packet.JHeader)
	 */
	public <T extends JHeader> T getHeader(T header) {
		return getHeader(header, 0);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderAccessor#getHeader(org.jnetpcap.packet.JHeader, int)
	 */
	public <T extends JHeader> T getHeader(T header, int instance) {
		check();

		final int index = this.state.findHeaderIndex(header.getId(), instance);
		if (index == -1) {
			return null;
		}

		return getHeaderByIndex(index, header);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderAccessor#getHeaderByIndex(int, org.jnetpcap.packet.JHeader)
	 */
	public <T extends JHeader> T getHeaderByIndex(int index, T header)
			throws IndexOutOfBoundsException {

		JHeader.State hstate = header.getState();
		this.state.peerHeaderByIndex(index, hstate);

		header.peer(this, hstate.getOffset(), hstate.getLength());
		header.setPacket(this); // Set the header's parent
		header.setIndex(index); // Set the header's index into packet structure
		header.decode(); // Call its decode routine if defined

		return header;

	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderAccessor#getHeaderCount()
	 */
	public int getHeaderCount() {
		return this.state.getHeaderCount();
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderAccessor#getHeaderIdByIndex(int)
	 */
	public int getHeaderIdByIndex(int index) {
		return this.state.getHeaderIdByIndex(index);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderAccessor#getHeaderInstanceCount(int)
	 */
	public int getHeaderInstanceCount(int id) {
		return this.state.getInstanceCount(id);
	}

	/**
	 * Gets the memory buffer.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the memory buffer
	 */
	protected JBuffer getMemoryBuffer(byte[] buffer) {
		pool.allocate(buffer.length, memory);
		memory.transferFrom(buffer);

		return memory;
	}

	/**
	 * Gets the memory buffer.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the memory buffer
	 * @throws PeeringException
	 *           the peering exception
	 */
	protected JBuffer getMemoryBuffer(ByteBuffer buffer) throws PeeringException {
		memory.peer(buffer);

		return memory;
	}

	/**
	 * Gets the memory buffer.
	 * 
	 * @param minSize
	 *          the min size
	 * @return the memory buffer
	 */
	protected JBuffer getMemoryBuffer(int minSize) {
		if (!memory.isInitialized() || memory.size() < minSize) {
			allocate(minSize);
		}

		return memory;
	}

	/**
	 * Gets the memory buffer.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the memory buffer
	 */
	protected JBuffer getMemoryBuffer(JBuffer buffer) {
		memory.peer(buffer);

		return memory;
	}

	/**
	 * Gets the packet wirelen.
	 * 
	 * @return the packet wirelen
	 */
	public int getPacketWirelen() {
		return getCaptureHeader().wirelen();
	}

	/**
	 * Gets the scanner.
	 * 
	 * @return the scanner
	 */
	@Deprecated
	public JScanner getScanner() {
		return defaultScanner;
	}

	/**
	 * Gets the packet's state structure.
	 * 
	 * @return the packet's state structure
	 */
	public State getState() {
		return state;
	}

	/**
	 * Gets the total size.
	 * 
	 * @return the total size
	 */
	public abstract int getTotalSize();

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderAccessor#hasHeader(int)
	 */
	public boolean hasHeader(int id) {
		return hasHeader(id, 0);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderAccessor#hasHeader(int, int)
	 */
	public boolean hasHeader(int id, int instance) {
		check();

		final int index = this.state.findHeaderIndex(id, instance);
		if (index == -1) {
			return false;
		}

		return true;
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderAccessor#hasHeader(org.jnetpcap.packet.JHeader)
	 */
	public <T extends JHeader> boolean hasHeader(T header) {
		return (state.get64BitHeaderMap(0) & (1L << header.getId())) != 0
				&& hasHeader(header, 0);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderAccessor#hasHeader(org.jnetpcap.packet.JHeader, int)
	 */
	public <T extends JHeader> boolean hasHeader(T header, int instance) {
		check();

		final int index = this.state.findHeaderIndex(header.getId(), instance);
		if (index == -1) {
			return false;
		}

		getHeaderByIndex(index, header);

		return true;
	}

	/**
	 * Remaining.
	 * 
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int remaining(int offset) {
		return size() - offset;
	}

	/**
	 * Remaining.
	 * 
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the int
	 */
	public int remaining(int offset, int length) {
		final int remaining = size() - offset;

		return (remaining >= length) ? length : remaining;
	}

	/**
	 * Scan.
	 * 
	 * @param id
	 *          the id
	 */
	public void scan(int id) {
		getDefaultScanner().scan(this, id, getCaptureHeader().wirelen());
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.nio.JMemory#toHexdump()
	 */
	@Override
	public String toHexdump() {
		if (state.isInitialized()) {
			return FormatUtils.hexdump(this);
		} else {
			byte[] b = this.getByteArray(0, this.size());
			return FormatUtils.hexdump(b);
		}
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		out.reset();
		try {
			out.format(this);
			return out.toString();
		} catch (Exception e) {
			throw new RuntimeException(out.toString(), e);
		}
	}
}
