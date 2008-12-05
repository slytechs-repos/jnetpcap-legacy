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
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JMemoryPool;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.nio.JMemoryPool.Block.Malloced;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;

/**
 * A native packet buffer object. This class references both packet data buffer
 * and decoded native packet structure. JPacket class is a subclass of a more
 * general JBuffer providing full access to raw packet buffer data. It also has
 * a reference to JPacket.State object which is peered, associated with, a
 * native packet state structure generated by the packet scanner, the JScanner.
 * <p>
 * The packet interface provides numerous methods for accessing the decoded
 * information. To check if any particular header is found within the packet's
 * data buffer at the time the packet was scanned, the user can use
 * {@link #hasHeader} methods. The method returns true if a particular header is
 * found within the packet data buffer, otherwise false. A convenience method
 * {@link #hasHeader(JHeader)} exists that performs both an existance check and
 * initializes the header instace supplied to point at the header within the
 * packet.
 * </p>
 * <p>
 * There are also numerous peer and deep copy methods. The peering methods do
 * not copy any buffers but simply re-orient the pointers to point at the source
 * peer structures to destination peer. The deep copy methods do copy physical
 * data out of buffers and entire structures using native copy functions, not in
 * java space.
 * </p>
 * 
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
		 * @param count
		 *          header counter, number of headers to calaculate in
		 * @return size in bytes
		 */
		public static native int sizeof(int count);

		/**
		 * @param size
		 */
		public State(int size) {
			super(STRUCT_NAME, size);
		}

		public State(Type type) {
			super(STRUCT_NAME, type);
		}

		public void cleanup() {
			super.cleanup();
		}

		/**
		 * Dump packet_state_t structure and its sub structures to textual debug
		 * output
		 * <p>
		 * Explanation:
		 * 
		 * <pre>
		 * sizeof(packet_state_t)=16
		 * sizeof(header_t)=8 and *4=32
		 * pkt_header_map=0x1007         // bitmap, each bit represets a header
		 * pkt_header_count=4            // how many header found
		 * // per header information (4 header found in this example)
		 * pkt_headers[0]=&lt;hdr_id=1  ETHERNET ,hdr_offset=0  ,hdr_length=14&gt;
		 * pkt_headers[1]=&lt;hdr_id=2  IP4      ,hdr_offset=14 ,hdr_length=60&gt;
		 * pkt_headers[2]=&lt;hdr_id=12 ICMP     ,hdr_offset=74 ,hdr_length=2&gt;
		 * pkt_headers[3]=&lt;hdr_id=0  PAYLOAD  ,hdr_offset=76 ,hdr_length=62&gt;
		 * 
		 * // hdr_id = numerical ID of the header, asssigned by JRegistry
		 * // hdr_offset = offset in bytes into the packet buffer
		 * // hdr_length = length in bytes of the entire header
		 * </pre>
		 * 
		 * Packet state is made up of 2 structures: packet_stat_t and an array of
		 * header_t, one per header. Total size in bytes is all of the header
		 * structures combined, that is 16 + 32 = 48 bytes. Each bit in the
		 * header_map represents the presence of that header type. The index of the
		 * bit is the numerical ID of the header. If 2 headers of the same type are
		 * present, they are both represented by a single bit in the bitmap. This
		 * way the implementation JPacket.hasHeader(int id) is a simple bit
		 * operation to test if the header is present or not.
		 * </p>
		 * 
		 * @return multiline string containing dump of the entire structure
		 */
		public native String debugString();

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

		/**
		 * @param memory
		 * @param offset
		 */
		public int peer(JMemory memory, int offset) {
			return super.peer(memory, offset, size());
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

		/**
		 * @param state
		 * @param offset
		 */
		public int peerTo(State state, int offset) {
			return super.peer(state, offset, state.size());
		}

		public int transferTo(JBuffer dst, int srcOffset, int length, int dstOffset) {
			return super.transferTo(dst, srcOffset, size(), dstOffset);
		}
	
		public int transferTo(byte[] dst, int dstOffset) {
			return super.transferTo(dst, 0, size(), dstOffset);
		}

		public int transferTo(byte[] dst, int srcOffset, int length, int dstOffset) {
			return super.transferTo(dst, srcOffset, size(), dstOffset);
		}


		public int transferTo(State dst) {
			return super.transferTo(dst, 0, size(), 0);
		}

		/**
		 * @param buffer
		 * @param offset
		 * @return
		 */
		public int peerTo(JBuffer buffer, int offset) {
			return super.peer(buffer, offset, size());
		}

		/**
		 * @param buffer
		 * @param offset
		 * @param size
		 */
		public int peerTo(JBuffer buffer, int offset, int size) {
			return super.peer(buffer, offset, size);
		}

		/**
     * @param memory
     * @param offset
     * @param size
     */
    public int peerTo(Malloced memory, int offset, int size) {
    	return super.peer(memory, offset, size);
    }
	}
	
	/**
	 * Default number of headers used when calculating memory requirements for an
	 * empty packet state structure. This value will be multiplied by the
	 * sizeof(header_t) structure and added to the size of the packet_t strcutre.
	 */
	public final static int DEFAULT_STATE_HEADER_COUNT = 20;

	private static JFormatter out = new TextFormatter(new StringBuilder());

	protected final State state = new State(Type.POINTER);
	
	protected static JMemoryPool pool = new JMemoryPool();

	protected final Malloced memory = new Malloced();
	
	protected int memoryOffset;
	
	protected Malloced getMemoryBuffer(byte[] buffer) {
		pool.allocate(buffer.length, memory);
		memory.transferFrom(buffer);
		
		return memory;
	}
	
	/**
	 * 
	 * @param buffer
	 * @return
	 */
	protected Malloced getMemoryBuffer(JBuffer buffer) {
		memory.peer(buffer);
		
		return memory;
	}
	
	/**
	 * 
	 * @param buffer
	 * @return
	 */
	protected Malloced getMemoryBuffer(ByteBuffer buffer) {
		memory.peer(buffer);
		
		return memory;
	}

	/**
	 * Retrieves a memory buffer, allocated if neccessary, at least minSize in
	 * bytes. If existing buffer is already big enough, it is returned, otherwise
	 * a new buffer is allocated and the existing one released.
	 * 
	 * @param minSize
	 *          minimum number of bytes required for the buffer
	 * @return the buffer
	 */
	protected Malloced getMemoryBuffer(int minSize) {
		if (!memory.isInitialized() || memory.size() < minSize) {
			allocate(minSize);
		}

		return memory;
	}

	/**
	 * 
	 * @return
	 */
	protected abstract int getTotalSize();

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
	public JPacket(Type type) {
		super(type);
	}

	/**
	 * Allocates a memory block and peers both the state and data buffer with it.
	 * The size parameter has to be big enough to hold both state and data for the
	 * packet.
	 * 
	 * @param size
	 *          amount of memory to allocate for packet data
	 * @param state
	 *          size of the state
	 */
	public JPacket(int size, int state) {
		super(Type.POINTER);

		allocate(size + state);
	}
	
	/**
	 * 
	 * @param size
	 */
	public void allocate(int size) {		
		pool.allocate(size, memory);
	}
	
	/**
	 * 
	 * @return
	 */
	public int getAllocatedMemorySize() {
		if (!memory.isInitialized()) {
			return 0;
		}
		
		return memory.size();
	}

	/**
	 * Gets the capture header as generated by the native capture library.
	 * 
	 * @return capture header
	 */
	public abstract JCaptureHeader getCaptureHeader();

	/**
	 * Peers the supplied header with the native header state structure and packet
	 * data buffer.
	 * 
	 * @param <T>
	 *          name of the header
	 * @param header
	 *          instance of a header object
	 * @return the supplied instance of the header
	 */
	public <T extends JHeader> T getHeader(T header) {
		return getHeader(header, 0);
	}

	/**
	 * Peers the supplied header with the native header state structure and packet
	 * data buffer. This method allows retrieval of a specific instance of a
	 * header if more than one instance has been found.
	 * 
	 * @param <T>
	 *          name of the header
	 * @param header
	 *          instance of a header object
	 * @param instance
	 *          instance number of the header since more than one header of the
	 *          same type can exist in the same packet buffer
	 * @return the supplied instance of the header
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
	 * Peers a header with specific index, not the numerical header ID assigned by
	 * JRegistry, of a header.
	 * 
	 * @param <T>
	 *          name of the header
	 * @param header
	 *          instance of a header object
	 * @param index
	 *          index into the header array the scanner has found
	 * @return the supplied header
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
	 * Gets number of headers found within the packet header. The last header may
	 * or may not be the builtin {@see Payload} header
	 * 
	 * @return
	 */
	public int getHeaderCount() {
		return this.state.getHeaderCount();
	}

	/**
	 * Gets the numerical ID of the header at specified index into header array as
	 * found by the packet scanner
	 * 
	 * @param index
	 *          index into the header array
	 * @return numerical ID of the header found at the specific index
	 */
	public int getHeaderIdByIndex(int index) {
		return this.state.getHeaderIdByIndex(index);
	}

	/**
	 * Gets number of headers with the same numerical ID as assigned by JRegistry
	 * within the same packet. For example Ip4 in ip4 packet would contain 2
	 * instances of Ip4 header.
	 * 
	 * @param id
	 *          numerical ID of the header to search for
	 * @return number of headers of the same type in the packet
	 */
	public int getHeaderInstanceCount(int id) {
		return this.state.getInstanceCount(id);
	}

	/**
	 * Gets the peered packet state object
	 * 
	 * @return packet native state
	 */
	public State getState() {
		return state;
	}

	public int getStateSize() {
		return state.size();
	}

	/**
	 * Checks if header with specified numerical ID exists within the decoded
	 * packet
	 * 
	 * @param id
	 *          protocol header ID as assigned by JRegistry
	 * @return true header exists, otherwise false
	 */
	public boolean hasHeader(int id) {
		return hasHeader(id, 0);
	}

	/**
	 * Check if requested instance of header with specified numerical ID exists
	 * within the decoded packet
	 * 
	 * @param id
	 *          protocol header ID as assigned by JRegistry
	 * @param instance
	 *          instance number of the specific header within the packet
	 * @return true header exists, otherwise false
	 */
	public boolean hasHeader(int id, int instance) {
		check();

		final int index = this.state.findHeaderIndex(id, instance);
		if (index == -1) {
			return false;
		}

		return true;
	}

	/**
	 * Check if requested instance of header with specified numerical ID exists
	 * within the decoded packet and if found peers the supplied header with the
	 * located header within the decoded packet. This method executes as hasHeader
	 * followed by getHeader if found more efficiently.
	 * 
	 * @param <T>
	 *          name of the header type
	 * @param header
	 *          protocol header object instance
	 * @return true header exists, otherwise false
	 */
	public <T extends JHeader> boolean hasHeader(T header) {
		return hasHeader(header, 0);
	}

	/**
	 * Check if requested instance of header with specified numerical ID exists
	 * within the decoded packet and if found peers the supplied header with the
	 * located header within the decoded packet. This method executes as hasHeader
	 * followed by getHeader if found more efficiently.
	 * 
	 * @param <T>
	 *          name of the header type
	 * @param header
	 *          protocol header object instance
	 * @param instance
	 *          instance number of the specific header within the packet
	 * @return true header exists, otherwise false
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
	 * Calculates the number of bytes remaining within the packet given a specific
	 * offset
	 * 
	 * @param offset
	 *          offset into the packet in bytes
	 * @return number of bytes remaining from specified offset
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

	/**
	 * Generates text formatted output using the default builtin formatter. The
	 * default is to generate TextFormatter that uses a StringBuilder for output
	 * buffer and gerate a single string that is returned from here.
	 * 
	 * @return formatted output of this packet
	 */
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
