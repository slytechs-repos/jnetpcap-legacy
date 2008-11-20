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

import java.io.IOException;
import java.nio.ByteBuffer;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemoryPool;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.nio.JMemoryPool.Block;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JPacket
    extends JBuffer {

	/**
	 * Class maintains the decoded packet state. The class is peered with
	 * <code>struct packet_state_t</code>
	 * 
	 * <pre>
	 * typedef struct packet_state_t {
	 * 	uint64_t pkt_header_map; // bit map of presence of headers
	 * 	char *pkt_data; // packet data buffer
	 * 	int32_t pkt_header_count; // total number of headers found
	 * 
	 * 	// Keep track of how many instances of each header we have
	 * 	uint8_t pkt_instance_counts[MAX_ID_COUNT];
	 * 	header_t pkt_headers[]; // One per header + 1 more for payload
	 * } packet_t;
	 * </pre>
	 * 
	 * and <code>struct header_t</code>
	 * 
	 * <pre>
	 * typedef struct header_t {
	 * 	int32_t hdr_id; // header ID
	 * 	uint32_t hdr_offset; // offset into the packet_t-&gt;data buffer
	 * 	int32_t hdr_length; // length of the header in packet_t-&gt;data buffer
	 * } header_t;
	 * 
	 * </pre>
	 * 
	 * <p>
	 * The methods in this <code>State</code> provide 3 sets of functions.
	 * Looking up global state of the packet found in packet_state_t structure,
	 * looking up header information in <code>struct header_t</code> by header
	 * ID retrieved from JRegistry and instance numbers, looking up header
	 * information by direct indexes into native maps and arrays. Instance numbers
	 * specify which instance of the header, if more than 1 exists in a packet.
	 * For example if there is a packet with 2 Ip4 headers such as
	 * 
	 * <pre>
	 * Ethernet-&gt;Ip4-&gt;Snmp-&gt;Ip4 
	 * or 
	 * Ethernet-&gt;Ip4-&gt;Ip4 (IP tunneled IP)
	 * </pre>
	 * 
	 * the first Ip4 header is instance 0 and the second Ip4 header is instance 2.
	 * You can use the method {@link #getInstanceCount(int)} to learn how many
	 * instance headers exists. That information is stored in the packet_state_t
	 * structure for efficiency.
	 * </p>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class State
	    extends JStruct {

		public final static String STRUCT_NAME = "packet_state_t";

		/**
		 * Returns the physical size of the packet_state_t structure. This is the
		 * amount of memory needed to keep the decoded state of a packet. Packet
		 * state information may be stored within the same storage buffer.
		 * 
		 * @return sizeof(struct packet_state_t)
		 */
		public static native int sizeof();

		public State() {
			super(STRUCT_NAME);
		}

		/**
		 * @param size
		 */
		public State(int size) {
			super(STRUCT_NAME, size);
		}

		public void cleanup() {
			super.cleanup();
		}

		public int findHeaderIndex(int id) {
			return findHeaderIndex(id, 0);
		}

		public native int findHeaderIndex(int id, int instance);

		public native long get64BitHeaderMap(int index);

		public native int getHeaderCount();

		public native int getHeaderIdByIndex(int index);

		public native int getInstanceCount(int id);

		public int peer(ByteBuffer peer) {
			return super.peer(peer);
		}

		public int peer(JBuffer peer) {
			return super.peer(peer, 0, size());
		}

		public int peer(JBuffer peer, int offset, int length)
		    throws IndexOutOfBoundsException {
			return super.peer(peer, offset, length);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JPeerable#peer(org.jnetpcap.nio.JMemoryPool.Block,
		 *      int, int)
		 */
		public int peer(JMemoryPool.Block peer, int offset, int length)
		    throws IndexOutOfBoundsException {
			return super.peer(peer, offset, length);
		}

		public int peer(State peer) {
			return super.peer(peer, 0, size());
		}

		public native int peerHeaderById(int id, int instance, JHeader.State dst);

		public native int peerHeaderByIndex(int index, JHeader.State dst)
		    throws IndexOutOfBoundsException;

		@Override
		public int transferTo(ByteBuffer dst) {
			return super.transferTo(dst, 0, size());
		}

		@Override
		public int transferTo(ByteBuffer dst, int srcOffset, int length) {
			return super.transferTo(dst, srcOffset, length);
		}

		public int transferTo(JBuffer dst) {
			return super.transferTo(dst, 0, size(), 0);
		}

		public int transferTo(JBuffer dst, int srcOffset, int length, int dstOffset) {
			return super.transferTo(dst, srcOffset, length, dstOffset);
		}

		public int transferTo(State dst) {
			return super.transferTo(dst, 0, size(), 0);
		}
	}

	private final State state;

	private static JFormatter out = new TextFormatter(new StringBuilder());
	
	/**
	 * A JPacket pointer. This is a pointer type constructor that does not
	 * allocate any memory but its intended to be pointed at a scanner packet_t
	 * structure that contains meta information about the structure of the packet
	 * data buffer.
	 * <p>
	 * JPacket constists of 2 peers. The first and the main memory peering is with
	 * the packet_state_t structure which stores information about the decoded
	 * state of the packet, another words the result of the scanned packet data
	 * buffer. The second peer is to the actual packet data buffer which is a
	 * seperate pointer.
	 * <h2>Peering struct packet_t</h2>
	 * This structure contains the "packet state". This is the decoded state which
	 * specifies what headers are in the buffer and at what offsets. This
	 * structure is the output of a JScanner.scan() method. The memory for this
	 * state can be anywhere, but by default JScanner stores it in a round-robin
	 * buffer it uses for decoding fast incoming packets. The state can easily be
	 * copied into another buffer for longer storage using such methods as
	 * {@link #transferStateTo} and {@link #transferStateAndDataTo} methods which
	 * will copy the packet state and/or data buffer into another memory area,
	 * such as a direct ByteBuffer or JBuffer.
	 * </p>
	 */
	public JPacket() {
		this.state = new State();
	}

	/**
	 * Allocates a new memory block for packet state and data (data follows
	 * immediately after state) then copies the supplied buffer into the data
	 * portion of the memory block. The supplied
	 * 
	 * @param buffer
	 *          buffer to copy data out of where position and limit ByteBuffer
	 *          properties set the boundaries of the buffer
	 */
	public JPacket(ByteBuffer buffer) {
		this(buffer.limit() - buffer.position());

		transferFrom(buffer);
	}

	/**
	 * Allocates a new memory block for packet state and data (data follows
	 * immediately after state.) Both packet state and data portions of the buffer
	 * are left in their default state.
	 * <p>
	 * Here is what memory block layout looks like. Where <code>x = sizeof(struct
	 * packet_stat_t)</code>
	 * and y = size
	 * 
	 * <pre>
	 * 0       x           y
	 * +-----------------&tilde;-+
	 * | state | data ...  |
	 * +-----------------&tilde;-+
	 * </pre>
	 * 
	 * Since Jpacket.State is a separate JMemory object from JPacket, both are
	 * peered to the same memory block at different offsets but only one remains
	 * the owner or responsible for deallocation of that memory block.
	 * </p>
	 * 
	 * @param size
	 *          amount of physical memory to allocate. The actual amount allocated
	 *          will be bigger than requested to also hold the packet state
	 *          information. Size can be 0 in which can only enough memory is
	 *          allocated to hold the packet state while the packet data portion
	 *          is not peered.
	 */
	public JPacket(int size) {
		if (size < 0) {
			throw new IllegalArgumentException("size must be positive");
		}
		this.state = new State(State.sizeof() + size);

		if (size > 0) {
			peer(state, State.sizeof(), size);
		}
	}

	/**
	 * Allocates a new memory block for packet state and data (data follows
	 * immediately after state) then copies the supplied buffer into the data
	 * portion of the memory block. The packet state is left uninitialized
	 * although it has memory allocated. The packet is suited to be scanned by
	 * JScanner.
	 * 
	 * @param buffer
	 *          buffer to copy data out of
	 */
	public JPacket(JBuffer buffer) {
		this(buffer.size());

		buffer.transferTo(this);
	}

	/**
	 * Allocates a new memory block big enough to just hold the new contents, for
	 * packet state and data (data follows immediately after state.) Both data and
	 * state are copied out of the src packet.
	 * 
	 * @param src
	 *          source packet to transfer state and data from
	 */
	public JPacket(JPacket src) {
		this(src.size());

		src.transferStateAndDataTo(this);
	}

	/**
	 * Allocates a new memory block for packet state and data (data follows
	 * immediately after state) out of a memory pool. Both data and state are
	 * copied out of the src packet.
	 * 
	 * @param src
	 *          source packet to transfer state and data from
	 */
	public JPacket(JPacket src, JMemoryPool pool) {
		this.state = new State();

		src.transferStateAndDataTo(this, pool);
	}

	/**
	 * Allocates enough memory to hold the src packet state and data using the
	 * supplied memory pool. The memory is allocated and peered with the internal
	 * state and data structures of this packet. Any previously bound or allocated
	 * memory by this packet object is released. Upon completion of this method,
	 * this object will be peered with enough memory to facilitate a transferTo
	 * from the src object to this object.
	 * <p>
	 * Typically this method is called to transfer data from a shared packet into
	 * a efficiently allocated memory block for longer term storage or processing.
	 * Here is an example of a <code>PcapPacketHandler.nextPacket</code> putting
	 * received packets into a more permanent storage and queue.
	 * 
	 * <pre>
	 * JMemoryPool pool = new JMemoryPool();
	 * Queue&lt;JPacket&gt; queue = // Some kind of user queue
	 * 
	 * public void nextPacket(PcapHeader header, JPacket shared, Strint msg) {
	 *   JPacket packet = new JPacket(); // Just a NULL pointer at this point
	 *   packet.allocate(shared, pool);  // Now pointing at physical mem
	 *   shared.transferStateAndDataTo(packet); // Native copy
	 *   
	 *   queue.put(packet); // The rest of the user logic in the handler
	 * }
	 * </pre>
	 * 
	 * In the above example shared packets are received. A new packet object is
	 * created that will reference packet state and data. A memory pool is used
	 * that allocates memory from the heap and peers (points the native pointers)
	 * at the new memory for packet object. The memory pool allocates memory in
	 * chunks which all the permanent packets reference. Once all the packets that
	 * utilize any particluar memory chunk are garbage collected, the entire chunk
	 * is freed. Also the same permanent packets, once no longer needed, can be
	 * reused as well by simply reallocating memory, while previously held memory
	 * will be released. This saves the user of an actual object creation.
	 * </p>
	 * </p>
	 * 
	 * @param src
	 *          source used to calculate the needed size for both state and data
	 * @param pool
	 *          memory pool from which to allocate
	 */
	public void allocate(JPacket src, JMemoryPool pool) {
		final int stateSize = src.state.size();
		final int size = src.size();

		Block block = pool.getBlock(stateSize + size);
		int offset = block.allocate(stateSize);
		this.state.peer(block, offset, stateSize);

		offset = block.allocate(size);
		this.peer(block, offset, size);
	}
	
	public abstract JCaptureHeader getCaptureHeader();

	/**
	 * @param <T>
	 * @param header
	 * @return
	 */
	public <T extends JHeader> T getHeader(T header) {
		return getHeader(header, 0);
	}

	/**
	 * @param <T>
	 * @param header
	 * @param instance
	 * @return
	 */
	public <T extends JHeader> T getHeader(T header, int instance) {
		check();

		final int index = this.state.findHeaderIndex(header.getId(), instance);
		if (index == -1) {
			return null;
		}

		return getHeaderByIndex(index, header);
	}

	/**
	 * @param <T>
	 * @param index
	 * @param header
	 * @return
	 * @throws IndexOutOfBoundsException
	 */
	public <T extends JHeader> T getHeaderByIndex(int index, T header)
	    throws IndexOutOfBoundsException {

		JHeader.State hstate = header.getState();
		this.state.peerHeaderByIndex(index, hstate);

		header.peer(this, hstate.getOffset(), hstate.getLength());
		header.decode(); // Call its decode routine if defined
		header.setPacket(this); // Set the header's parent

		return header;

	}

	/**
	 * @return
	 */
	public int getHeaderCount() {
		return this.state.getHeaderCount();
	}

	/**
	 * @param index
	 * @return
	 */
	public int getHeaderIdByIndex(int index) {
		return this.state.getHeaderIdByIndex(index);
	}

	/**
	 * @param id
	 * @return
	 */
	public int getHeaderInstanceCount(int id) {
		return this.state.getInstanceCount(id);
	}

	/**
	 * @return
	 */
	public State getState() {
		return state;
	}

	public boolean hasHeader(int id) {
		return hasHeader(id, 0);
	}

	public boolean hasHeader(int id, int instance) {
		check();

		final int index = this.state.findHeaderIndex(id, instance);
		if (index == -1) {
			return false;
		}

		return true;
	}

	/**
	 * @param <T>
	 * @param header
	 * @return
	 */
	public <T extends JHeader> boolean hasHeader(T header) {
		return hasHeader(header, 0);
	}

	/**
	 * @param <T>
	 * @param header
	 * @param instance
	 * @return
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JPeerable#peer(org.jnetpcap.nio.JMemoryPool.Block,
	 *      int, int)
	 */
	public int peer(JMemoryPool.Block peer, int offset, int length)
	    throws IndexOutOfBoundsException {
		return super.peer(peer, offset, length);
	}

	/**
	 * The backing buffer becomes the physical memory JPacket is pointing to, but
	 * this instance does not become the owner of the memory. The peered buffer is
	 * still the owner of the memory and responsible for memory managment.
	 * 
	 * @param bytebuffer
	 */
	public void peerData(ByteBuffer buffer) {
		super.peer(buffer);
	}

	/**
	 * The backing buffer becomes the physical memory JPacket is pointing to, but
	 * this instance does not become the owner of the memory. The peered buffer is
	 * still the owner of the memory and responsible for memory managment.
	 * 
	 * @param buffer
	 */
	public void peerData(JBuffer buffer) {
		super.peer(buffer);
	}

	/**
	 * Peers packet to a JBuffer that contains both state and packet data within
	 * the same buffer. Both state and data are peered with the physical memory of
	 * src. The state header structure in memory is expected to directly precede
	 * the packet data.
	 * 
	 * @param buffer
	 */
	public void peerStateAndData(JBuffer buffer) {
		state.peer(buffer, 0, State.sizeof());
		peer(buffer, state.size(), buffer.size());
	}

	/**
	 * @param packet
	 */
	public void peerStateAndData(JPacket packet) {
		super.peer(packet);
		state.peer(packet.state);
		
		getCaptureHeader().transferTo(packet.getCaptureHeader());
	}

	/**
	 * @param offset
	 * @return
	 */
	public int remaining(int offset) {
		return size() - offset;
	}

	/**
	 * Calculates the remaining number of bytes within the packet buffer taking
	 * into account offset and length of a header supplied. The smaller of the 2
	 * is returned. This should typically be the length field unless the header
	 * has been truncated and remaining number of bytes is less.
	 * 
	 * @param offset
	 *          offset of the header to take into account
	 * @param length
	 *          length of the header
	 * @return smaller number of bytes either remaining or legth
	 */
	public int remaining(int offset, int length) {
		final int remaining = size() - offset;

		return (remaining >= length) ? length : remaining;
	}

	public int transferDataTo(ByteBuffer dst) {
		return transferTo(dst);
	}

	public int transferDataTo(JBuffer dst) {
		return transferTo(dst);
	}

	public int transferDataTo(JBuffer dst, int srcOffset, int length,
	    int dstOffset) {
		return transferTo(dst, srcOffset, length, dstOffset);
	}

	public int transferDataTo(JPacket dst) {
		return super.transferTo(dst);
	}

	public int transferStateAndDataTo(ByteBuffer dst) {
		int p = dst.position();
		int count = state.transferTo(dst);

		dst.position(p + count);

		count += transferTo(dst);

		dst.position(p);
		return count;
	}

	public int transferStateAndDataTo(JBuffer dst) {
		int count = state.transferTo(dst);
		count += transferTo(dst, 0, size(), count);

		return count;
	}

	public int transferStateAndDataTo(JBuffer dst, int srcDataOffset,
	    int dataLength, int dstOffset) {
		int count = state.transferTo(dst, 0, state.size(), dstOffset);
		count += transferTo(dst, srcDataOffset, dataLength, dstOffset + count);

		return count;
	}

	public int transferStateAndDataTo(JPacket dst) {
		int count = state.transferTo(dst.state);
		count += super.transferTo(dst);

		return count;
	}

	/**
	 * Transfers state and data to dst while allocating memory out of the pool.
	 * Any previously held memory by dst is released. To transfer to dst without
	 * new memory allocation use {@link #transferStateAndDataTo(JPacket).
	 * 
	 * @param dst
	 * @param pool
	 * @return
	 */
	public int transferStateAndDataTo(JPacket dst, JMemoryPool pool) {

		final int stateSize = state.size();
		final int size = super.size();

		final Block block = pool.getBlock(stateSize + size);
		dst.state.peer(block, block.allocate(stateSize), stateSize);
		dst.peer(block, block.allocate(size), size);

		return transferStateAndDataTo(dst);
	}

	public int transferStateTo(ByteBuffer dst) {
		return state.transferTo(dst);
	}

	public int transferStateTo(JBuffer dst) {
		return state.transferTo(dst);
	}

	public int transferStateTo(JBuffer dst, int dstOffset) {
		return state.transferTo(dst, 0, state.size(), dstOffset);
	}

	public int transferStateTo(JPacket dst) {
		return state.transferTo(dst.state);
	}

	public String toString() {
		out.reset();
		try {
			out.format(this);
			return out.toString();
		} catch (IOException e) {
			throw new IllegalStateException(
			    "internal error, StringBuilder threw IOException");
		}
	}
}
