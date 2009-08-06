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
package org.jnetpcap.nio;

import java.nio.ByteBuffer;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PeeringException;
import org.jnetpcap.packet.format.FormatUtils;

/**
 * A base class for all other PEERED classes to native c structures. The class
 * only contains the physical address of the native C structure. The class also
 * contains a couple of convenience methods for allocating memory for the
 * structure to be peered as well as doing cleanup and freeing up that memory
 * when object is finalized().
 * <p>
 * This is one of the most important classes within jNetPcap library. It is
 * responsible for most of the memory allocation and management behind the
 * scenes of all jNetPcap native methods.
 * </p>
 * 
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JMemory {

	/**
	 * Used in special memory allocation. Allows the user to specify the type
	 * allocation required of this memory object.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Type {
		/**
		 * Peered object is being created as a reference pointer and has no memory
		 * allocated on its own. It is expected that new object will be peered with
		 * exising memory location. The same concept as a native memory pointer,
		 * think void * in C.
		 */
		POINTER
	}

	/**
	 * Name of the native library that wraps around libpcap and extensions
	 */
	public static final String JNETPCAP_LIBRARY_NAME = "jnetpcap";

	/**
	 * Convenience constant that is synonym as JMemory.Type.POINTER. Since this
	 * type constant is used so often, it is made as a in-class constant to make
	 * it easier to access.
	 */
	public static final JMemory.Type POINTER = JMemory.Type.POINTER;

	/**
	 * Load the native library and initialize JNI method and class IDs.
	 */
	static {
		try {
			System.loadLibrary(JNETPCAP_LIBRARY_NAME);

			Pcap.isInjectSupported();

			initIDs();
		} catch (Exception e) {
			System.err.println(e.getClass().getName() + ": "
			    + e.getLocalizedMessage());
			throw new ExceptionInInitializerError(e);
		}
	}

	/**
	 * Initializes JNI ids.
	 */
	private static native void initIDs();

	/**
	 * Returns the total number of active native memory bytes currently allocated
	 * that have not been deallocated as of yet. This number can be calculated by
	 * the following formula:
	 * 
	 * <pre>
	 * totalAllocated() - totalDeAllocated()
	 * </pre>
	 * 
	 * @return number of native memory bytes still allocated
	 */
	public static long totalActiveAllocated() {
		return totalAllocated() - totalDeAllocated();
	}

	/**
	 * Returns total number of allocate calls through JMemory class. The memory is
	 * allocated by JMemory class using native "malloc" calls and is not normally
	 * reported by JRE memory usage.
	 * 
	 * @return total number of function calls made to malloc since JMemory class
	 *         was loaded into memory
	 */
	public native static long totalAllocateCalls();

	/**
	 * Returns total number of bytes allocated through JMemory class. The memory
	 * is allocated by JMemory class using native "malloc" calls and is not
	 * normally reported by JRE memory usage.
	 * 
	 * @return total number of bytes allocated since JMemory class was loaded into
	 *         memory
	 */
	public native static long totalAllocated();

	/**
	 * Returns the number of memory segments that were allocated by JMemory class
	 * in the range of 0 to 255 bytes in size. This is number of segments, not
	 * amount of memory allocated.
	 * 
	 * @return the total number of memory segments in this size
	 */
	public native static long totalAllocatedSegments0To255Bytes();

	/**
	 * Returns the number of memory segments that were allocated by JMemory class
	 * in the range of 256 bytes or above in size. This is number of segments, not
	 * amount of memory allocated.
	 * 
	 * @return the total number of memory segments in this size
	 */
	public native static long totalAllocatedSegments256OrAbove();

	/**
	 * Returns total number of deallocate calls through JMemory class. The memory
	 * is allocated by JMemory class using native "free" calls and is not normally
	 * reported by JRE memory usage.
	 * 
	 * @return total number of function calls made to free since JMemory class was
	 *         loaded into memory
	 */
	public native static long totalDeAllocateCalls();

	/**
	 * Returns total number of bytes deallocated through JMemory class. The memory
	 * is deallocated by JMemory class using native "free" calls and is not
	 * normally reported by JRE memory usage.
	 * 
	 * @return total number of bytes deallocated since JMemory class was loaded
	 *         into memory
	 */
	public native static long totalDeAllocated();

	/**
	 * Used to keep a reference tied with this memory object.
	 */
	@SuppressWarnings("unused")
	private volatile Object keeper = null;

	/**
	 * Specifies if this object owns the allocated memory. Using
	 * JMemory.allocate() automatically makes the object owner of the allocated
	 * memory block. Otherwise it is assumed that the {@link #physical} memory
	 * pointer is referencing a memory block not owned by this object, and
	 * therefore will not try and deallocate that memory upon cleanup.
	 * <p>
	 * Remember that physical field is set from within a native call and any
	 * object subclassing JMemory can be made to reference any memory location
	 * including another JMemory object's allocated memory or anywhere for that
	 * matter.
	 * </p>
	 */
	private volatile boolean owner = false;

	/**
	 * Physical address of the peered structure. This variable is modified outside
	 * java space as C structures are bound to it. Subclasses implement methods
	 * and fields that understand the exact structure.
	 */
	private volatile long physical;

	/**
	 * Only maintained when owner == true This variable is modifiable by JNI code
	 * even though is set to final. Setting to final prevents any java code from
	 * modifying this variable. JNI code only modifies this variable under 2
	 * conditions. When allocating a new native memory block, it sets the size of
	 * the memory block allocated and when its deallocated, it resets the variable
	 * back to 0.
	 * <p>
	 * The variable is needed prevent anyone from changing the size field, which
	 * can be changed at any time out of bound of actually allocated memory block.
	 * </p>
	 */
	private final int physicalSize;

	/**
	 * Number of byte currently allocated
	 */
	private volatile int size;

	/**
	 * Keeps track of JNI global references. As long as there is a java object
	 * referencing the JReference container, the JNI references will not be
	 * released. Null means that there are no references.
	 */
	private JReference references;

	{
		physicalSize = 0;
	} // Prevent compiler optimizing away to 0

	/**
	 * @param peer
	 */
	public JMemory(ByteBuffer peer) {
		this(peer.limit() - peer.position());

		transferFrom(peer);
	}

	/**
	 * Pre-allocates memory for any structures the subclass may need to use.
	 * 
	 * @param size
	 *          number of bytes to pre-allocate allocate
	 */
	public JMemory(int size) {
		if (size <= 0) {
			throw new IllegalArgumentException("size must be greater than 0");
		}

		allocate(size);
	}

	/**
	 * Performs a deep copy into a newly allocated memory block
	 * 
	 * @param src
	 */
	public JMemory(JMemory src) {
		allocate(src.size);

		src.transferTo(this);
	}

	/**
	 * No memory pre-allocation constructor
	 */
	public JMemory(Type type) {
		if (type != Type.POINTER) {
			throw new IllegalArgumentException("Only POINTER types are supported");
		}

		this.size = 0;
	}

	/**
	 * Method allocates native memory to hold the subclassed C structure if the
	 * size is knows ahead of time. The physical field is set to the address of
	 * the allocated structure.
	 * 
	 * @param size
	 *          number of bytes to allocate.
	 */
	private native void allocate(int size);

	/**
	 * Checks if this peered object is initialized. This method throws
	 * IllegalStateException if not initialized and does not return any values.
	 * Its intended to as an assert mechanism
	 * 
	 * @throws IllegalStateException
	 *           if peered object is not initialized this unchecked exception will
	 *           be thrown, otherwise it will exit silently
	 */
	public void check() throws IllegalStateException {
		if (physical == 0) {
			throw new IllegalStateException(
			    "peered object not synchronized with native structure");
		}
	}

	/**
	 * Called to clean up and release any allocated memory. This method should be
	 * overriden if the allocated memory is not simply a single memory block and
	 * something more complex. This method is safe to call at anytime even if the
	 * object does not hold any allocated memory or is not the owner of the memory
	 * it is peered with. The method will reset this object to orignal unpeered
	 * state releasing any allocated and own memory at the same time if
	 * neccessary.
	 */
	protected native void cleanup();

	/**
	 * Default finalizer which checks if there is any memory to free up.
	 */
	@Override
	protected void finalize() {
		cleanup();
	}

	/**
	 * Checks if this peered object is initialized. This method does not throw any
	 * exceptions.
	 * 
	 * @return if initialized true is returned, otherwise false
	 */
	public boolean isInitialized() {
		return physical != 0;
	}

	public final boolean isOwner() {
		return this.owner;
	}

	/**
	 * Peers the src structure with this instance. The physical memory that the
	 * src peered object points to is set to this instance. The owner flag is not
	 * copied and src remains at the same state as it did before. This instance
	 * does not become the owner of the memory.
	 * <p>
	 * Further more, since we are peering with a ByteBuffer, the actual memory
	 * that is peered is between ByteBuffer's position and limit properties. Those
	 * 2 properties determine which portion of the memory that will be peered.
	 * This allows a larger ByteBuffer to be peered with different objects
	 * providing rudimentary memory allocation mechanism.
	 * </p>
	 * <p>
	 * Lastly care must be taken, to ensure that the lifespans do not conflict.
	 * The memory that we are peering to must not be deallocated prior the
	 * termination of the lifespan of this object or at minimum calling
	 * {@link #cleanup()} method to ensure that this object no longer references
	 * memory which may have been or become deallocated.
	 * </p>
	 * 
	 * @param peer
	 *          The ByteBuffer whose allocated native memory we want to peer with.
	 *          The ByteByffer must be if direct buffer type which can be checked
	 *          using ByteBuffer.isDirect() call.
	 * @throws PeeringException
	 * @see ByteBuffer#isDirect()
	 */
	protected native int peer(ByteBuffer peer) throws PeeringException;

	/**
	 * Peers the peer structure with this instance. The physical memory that the
	 * peer object points to is set to this instance. The owner flag is not copied
	 * and peer remains at the same state as it did before. This instance does not
	 * become the owner of the memory.
	 * 
	 * @param peer
	 *          the object whose allocated native memory we want to peer with
	 */
	protected int peer(JMemory peer) {
		return peer(peer, 0, peer.size());
	}

	/**
	 * Peers the peer structure with this instance. The physical memory that the
	 * peer object points to is set to this instance. The owner flag is not copied
	 * and peer remains at the same state as it did before. This instance does not
	 * become the owner of the memory. The function allows peering to a sub
	 * portion of the peer given the specified offset and length. The function
	 * strictly checks and inforces the bounds of the request to guarrantee that
	 * peer is not allowed to access physical memory outside of actual peer range.
	 * 
	 * @param peer
	 *          object memory block to peer with
	 * @param offset
	 *          offset into the memory block
	 * @param length
	 *          amount of memory to peer with
	 * @throws IndexOutOfBoundsException
	 *           if the specified memory offset and length have negative or out of
	 *           bounds of peer objects address space
	 */
	protected int peer(JMemory peer, int offset, int length)
	    throws IndexOutOfBoundsException {
		if (offset < 0 || length < 0
		    || (!peer.owner && offset + length > peer.size) || peer.owner
		    && offset + length > peer.physicalSize) {
			throw new IllegalArgumentException("Invalid [" + offset + ","
			    + (offset + length) + "," + length + ") range.");
		}

		cleanup(); // Clean up any memory we own before we give it up

		this.physical = peer.physical + offset;
		this.size = length;

		/**
		 * For specific reasons, we can never be the owner of the peered structure.
		 * The owner should remain the object that initially created or was created
		 * to manage the physical memory. The reasons are as follows:
		 * <ul>
		 * <li> Memory could be a revolving buffer
		 * <li> Memory allocation could have been complex with sub structures that
		 * need to be deallocated
		 * <li> The src object may have been passed around and references stored to
		 * it elsewhere. If we are GCed before src and we free up the memory the
		 * original src object would become unstable
		 * </ul>
		 */
		this.owner = false;

		if (peer.keeper == null) {
			this.keeper = peer;
		} else {
			this.keeper = peer.keeper;
		}

		/*
		 * Transfer the JNI global references
		 */
		if (peer.references != null) {
			this.references = peer.references;
		}

		return size;

	}

	/**
	 * Changes the size of this memory block. The size can not be changed passed
	 * the physical size.
	 * 
	 * @param size
	 *          length in bytes for this memory buffer
	 */
	protected void setSize(int size) {
		if (!owner) {
			throw new IllegalAccessError(
			    "object not owner of the memory block. Can not change size,"
			        + " must use peer() to change rereference properties");
		}

		if (size < 0 || size > physicalSize) {
			throw new IllegalArgumentException(
			    "size is out of bounds (physical size=" + physicalSize
			        + ", requested size=" + size);
		}

		this.size = size;
	}

	/**
	 * Returns the size of the memory block that this peered structure is point
	 * to. This object does not neccessarily have to be the owner of the memory
	 * block and could simply be a portion of the over all memory block.
	 * 
	 * @return number of byte currently allocated
	 */
	public int size() {
		if (isInitialized() == false) {
			throw new NullPointerException("jmemory not initialized");
		}

		return size;
	}

	/**
	 * A debug method, similar to toString() which converts the contents of the
	 * memory to textual hexdump.
	 * 
	 * @return multi-line hexdump of the entire memory region
	 */
	public String toHexdump() {
		JBuffer b = new JBuffer(Type.POINTER);
		b.peer(this);

		return FormatUtils.hexdumpCombined(b.getByteArray(0, size), 0, 0, true,
		    true, true);
	}

	/**
	 * Returns a debug string about this JMemory state. Example:
	 * 
	 * <pre>
	 * JMemory@b052fa8: size=1506, owner=nio.JMemoryPool$Block.class(size=10240/offset=4064)
	 * </pre>
	 * 
	 * <ul>
	 * <li> hex nuber, is physical memory location
	 * <li> size = number of bytes of this memory object
	 * <li> owner = the class name of the object that owns the physical memory
	 * <li> isOwner = if true, means that this object is the owner of physical
	 * memory
	 * <li> size in parenthesis = the size of the physical memory allocated by the
	 * owner
	 * <li> offset in parenthesis = the offset into the physical memory block of
	 * this memory object
	 * </ul>
	 * 
	 * @return a summary string describing the state of this memory object
	 */
	public String toDebugString() {
		StringBuilder b = new StringBuilder();

		b.append("JMemory: JMemory@").append(Long.toHexString(physical)).append(
		    ": ");
		b.append("size=").append(size).append(" bytes");
		if (!owner) {
			b.append("\n").append("JMemory: owner=").append(
			    keeper.getClass().getName().replaceAll("org.jnetpcap.", "")).append(
			    ".class");
			if (keeper instanceof JMemory) {
				JMemory k = (JMemory) keeper;
				b.append("(size=").append(k.physicalSize);
				b.append("/offset=").append(this.physical - k.physical);
				b.append(')');
			}
		} else {
			b.append("\n").append("JMemory: isOwner=").append(owner);
		}

		if (references == null) {
			b.append("\nJMemory: references(null)");
		} else {
			b.append("\nJMemory: references(").append(references.toDebugString())
			    .append(')');
		}

		return b.toString();
	}

	/**
	 * Checks if physical memory pointed to by this object, is owned either by
	 * this JMemory based object or the actual owner is also JMemory based. This
	 * method provides a check if the physical memory pointed to by this object
	 * has been allocated through use of one of JMemory based functions or outside
	 * its memory management scope. For example, memory allocated by libpcap
	 * library will return false. While packets that copied their state to new
	 * memory will return true.
	 * 
	 * @return true if physical memory is managed by JMemory, otherwise false
	 */
	public boolean isJMemoryBasedOwner() {
		return physical != 0 && (owner || keeper instanceof JMemory);
	}

	/**
	 * A debug method, similar to toString() which converts the contents of the
	 * memory to textual hexdump.
	 * 
	 * @param length
	 *          maximum number of bytes to dump to hex output
	 * @param address
	 *          flag if set to true will print out address offset on every line
	 * @param text
	 *          flag if set to true will print out a text characters at the end of
	 *          everyline
	 * @param data
	 *          flag if set to true will print out raw HEX data on every line
	 * @return multi-line hexdump of the entire memory region
	 */
	public String toHexdump(
	    int length,
	    boolean address,
	    boolean text,
	    boolean data) {
		length = (length < size) ? length : size;
		JBuffer b = new JBuffer(Type.POINTER);
		b.peer(this);

		return FormatUtils.hexdumpCombined(b.getByteArray(0, length), 0, 0,
		    address, text, data);
	}

	/**
	 * Copies contents of byte array to memory
	 * 
	 * @param buffer
	 *          source buffer
	 * @return number of bytes copied
	 */
	protected int transferFrom(byte[] buffer) {
		return transferFrom(buffer, 0, buffer.length, 0);
	}

	/**
	 * Copies contents of byte array to memory
	 * 
	 * @param buffer
	 *          source buffer
	 * @param srcOffset
	 *          starting offset into the byte array
	 * @param length
	 *          number of bytes to copy
	 * @param dstOffset
	 *          starting offset into memory buffer
	 * @return number of bytes copied
	 */
	protected native int transferFrom(
	    byte[] buffer,
	    int srcOffset,
	    int length,
	    int dstOffset);

	/**
	 * Copies data from memory from direct byte buffer to this memory
	 * 
	 * @param src
	 *          source buffer
	 * @return actual number of bytes that was copied
	 */
	protected int transferFrom(ByteBuffer src) {
		return transferFrom(src, 0);
	}

	/**
	 * Copies data from memory from direct byte buffer to this memory
	 * 
	 * @param src
	 *          source buffer
	 * @param dstOffset
	 *          offset into our memory location
	 * @return actual number of bytes that was copied
	 */
	protected int transferFrom(ByteBuffer src, int dstOffset) {
		if (src.isDirect()) {
			return transferFromDirect(src, 0);
		} else {
			return transferFrom(src.array(), src.position(), src.limit()
			    - src.position(), 0);
		}
	}

	/**
	 * Copies data from memory from direct byte buffer to this memory
	 * 
	 * @param src
	 *          source buffer
	 * @param dstOffset
	 *          offset into our memory location
	 * @return actual number of bytes that was copied
	 */
	protected native int transferFromDirect(ByteBuffer src, int dstOffset);

	/**
	 * A special method that allows one object to transfer ownership of a memory
	 * block. The supplied JMemory object must already be the owner of the memory
	 * block. This policy is strictly enforced. If the ownership transfer
	 * succeeds, this memory object will be responsible for freeing up memory
	 * block when this object is garbage collected or the user calls
	 * JMemory.cleanup() method.
	 * <h2>Warning!</h2>
	 * Care must be taken to only transfer ownership for simple memory
	 * allocations. If a complex memory allocation was used, one that sub
	 * allocates other memory blocks which are referenced from the original memory
	 * block, to avoid creating memory leaks. It is best practice to sub allocate
	 * other memory blocks using JMemory class which will properly manage that
	 * memory block and ensure that it will freed properly as well.
	 * 
	 * @param memory
	 *          memory block to transfer the ownership from
	 * @return if tranfer succeeded true is returned, otherwise false.
	 */
	protected boolean transferOwnership(JMemory memory) {
		if (!memory.owner || this.physical == 0 || this.physical != memory.physical) {
			return false;
		}

		memory.owner = false;
		this.owner = true;
		this.keeper = null; // Release any kept references

		return true;
	}

	/**
	 * Copies data from memory to byte array
	 * 
	 * @param buffer
	 *          destination buffer starting offset in byte array
	 * @return number of bytes copied
	 */
	protected int transferTo(byte[] buffer) {
		return transferTo(buffer, 0, buffer.length, 0);
	}

	/**
	 * Copies data from memory to byte array
	 * 
	 * @param buffer
	 *          destination buffer
	 * @param srcOffset
	 *          starting offset in memory
	 * @param length
	 *          number of bytes to copy
	 * @param dstOffset
	 *          starting offset in byte array
	 * @return number of bytes copied
	 */
	protected native int transferTo(
	    byte[] buffer,
	    int srcOffset,
	    int length,
	    int dstOffset);

	/**
	 * Copies teh contents of this memory to buffer
	 * 
	 * @param dst
	 *          destination buffer
	 * @return actual number of bytes that was copied
	 */
	public int transferTo(ByteBuffer dst) {
		return transferTo(dst, 0, size);
	}

	/**
	 * Copies teh contents of this memory to buffer
	 * 
	 * @param dst
	 *          destination buffer
	 * @param srcOffset
	 *          offset in source
	 * @param length
	 *          number of bytes to copy
	 * @return number of bytes copied
	 */
	public int transferTo(ByteBuffer dst, int srcOffset, int length) {
		if (dst.isDirect()) {
			return transferToDirect(dst, srcOffset, length);
		} else {
			int o = transferTo(dst.array(), 0, length, dst.position());
			dst.position(dst.position() + o);

			return o;
		}
	}

	/**
	 * Transfers the contents of this memory to buffer.
	 * 
	 * @param dst
	 *          destination buffer
	 * @param srcOffset
	 *          offset in source
	 * @param length
	 *          number of bytes to copy
	 * @param dstOffset
	 *          offset in destination buffer
	 * @return number of bytes copied
	 */
	public int transferTo(JBuffer dst, int srcOffset, int length, int dstOffset) {
		return transferTo((JMemory) dst, srcOffset, length, dstOffset);
	}

	/**
	 * Copied the entire contents of this memory to destination memory
	 * 
	 * @param dst
	 *          destination memory
	 * @return number of bytes copied
	 */
	protected int transferTo(JMemory dst) {
		return transferTo(dst, 0, size, 0);
	}

	/**
	 * Copied the entire contents of this memory to destination memory
	 * 
	 * @param dst
	 *          destination memory
	 * @param srcOffset
	 *          offset in source
	 * @param length
	 *          number of bytes to copy
	 * @param dstOffset
	 *          offset in destination buffer
	 * @return number of bytes copied
	 */
	protected native int transferTo(
	    JMemory dst,
	    int srcOffset,
	    int length,
	    int dstOffset);

	/**
	 * @param dst
	 * @param srcOffset
	 * @param length
	 * @return actual number of bytes that was copied
	 */
	private native int transferToDirect(ByteBuffer dst, int srcOffset, int length);
}