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
import java.nio.ByteOrder;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.format.FormatUtils;

/**
 * Native memory management. This class has 3 modes of operation.
 * <ul>
 * <li> Mode 1: As owner of a memory block. The owner is responsible for
 * deallocation of memory when object is finilized.</li>
 * <li> Mode 2: As peer to another JMemory block of native memory. This object
 * is not responsible for deallocation of the memory, but must check if the
 * owner is still alive or valid.</li>
 * <li> Mode 3: As volatile memory proxy. This object acts like the owner of the
 * memory but in reality its not and will not deallocate the memory it points
 * to. It can however be used as a reset switch to invalidate its memory so any
 * peered JMemory objects are deactivated as well.
 * </ul>
 * <p>
 * This is one of the most important classes within jNetPcap library. It is
 * responsible for most of the memory allocation and management behind the
 * scenes of all jNetPcap native methods.
 * </p>
 * <h3> Mode 1: as owner</h3>
 * In owner mode, this object is responsible for possibly the allocation and
 * later deallocation of a memory block when this object is finalized. Owner
 * objects (as determined by checking if owner property is set to null), may
 * never be used or reused as peering objects. This operation is prohibited and
 * will result in an exception.
 * <p>
 * In owner mode, <code>JMemory</code> properties have the following
 * functions; <code>physical</code> holds the physical memory address of the
 * start of the memory block that will be deallocated (presumably using C free
 * function). If this property is null or zero, that means that this object is
 * no longer usable.
 * </p>
 * <p>
 * <code>size</code> holds the number of bytes that that have been allocated
 * and will be freedup. This property is mainly used in peering process to
 * enforce the boundaries of the requested memory to be peered. It is also used
 * as a flag to indicate that no memory deallocation should occur. If the
 * <code>size</code> is set to zero, then deallocation will no be done. This
 * allows <code>JMemory</code> in owner mode, be utilized for other purposes
 * such as in <code>JFunction</code> class which holds a reference to a
 * function pointer.
 * </p>
 * <p>
 * <code>owner</code> in owner mode this property is always null. Thus when
 * phsyical or size is not zero or null and owner property is null, then this
 * object is presumed to be in owner mode.
 * </p>
 * <h3> Mode 2: as peer</h3>
 * Peering means that 2 objects one being the owner of a native memory block and
 * the second a peer, will share and point at the exact same memory block.
 * <p>
 * A peer will have its <code>physical</code> address property point into the
 * owner's memory block anywhere between zero offset and end of the native
 * memory block. More formally peer will point into owner memory block in the
 * following range [physical + 0, physical + size).
 * </p>
 * <p>
 * <code>size</code> property in a peer, can be of any size, as long as it
 * does not go outside the boundaries of the memory block as defined by the
 * owner. Size may never be zero.
 * </p>
 * <p>
 * <code>owner</code> property references either a <code>JMemory</code>
 * object or another native memory managed object such as
 * <code>java.nio.ByteBuffer</code>. In peered mode, the owner property may
 * never be null. If a <code>JMemory</code> object has the <code>owner</code>
 * property as null, it may never be peered again with another object. A newly
 * allocated object in this mode must set its <code>owner</code> property to
 * itself as the owner, indicating that its in peering mode.
 * </p>
 * <h3> Mode 3: as proxy</h3>
 * A proxy memory mode is used for managing volatile memory, memory that is not
 * under <code>JMemory</code> control and may through various circumstances
 * become unusable. <code>JMemory</code> works in conjuction with a subclass
 * <code>JProxyMemory</code> to implement this mode. In proxy mode objects may
 * not be used directly by other subclasses therefore this type of object is
 * only suitable for peering with.
 * <p>
 * <code>physical</code> property just like in the owner mode, points at a
 * memory block. Unlike the owner mode, this <code>JMemory</code> object will
 * not deallocate this memory, but may act as a double pointer, or a proxy for
 * other peered objects. The <code>JProxyMemory</code> object may be
 * instructed to invalidate its memory and any existing peered objects will also
 * become invalidated.
 * </p>
 * <p>
 * <code>size</code> same as size in owner mode.
 * </p>
 * <p>
 * <code>owner</code> property contains a reference to the corresponding java
 * owner of the memory. For example if a <code>Pcap</code> object is
 * associated with this proxy memory, then that object is set as an owner. Since
 * <code>JProxyMemory</code> objects are not directly usable through either
 * java or native APIs, the only real use for this property is cosmetic. The
 * owner property may help in debugging. The actual object it points to is
 * irrelavent with the exception that it is meanigfull in debugging. So for
 * example when proxy is setup for libpcap managed memory block, assigning the
 * reference to a <code>Pcap</code> object is meaningfull as debugging output
 * will show that the memory a peer is pointing to belongs to libpcap, and was
 * not <code>JMemory</code> allocated.
 * </p>
 * 
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class JMemory {

	public enum Flag {
		ACTIVE(JMemory.JMEMORY_FLAG_ACTIVE, 'A'),
		BIG_ENDIAN(JMemory.JMEMORY_FLAG_BIG_ENDIAN, 'E'),
		DATA(JMemory.JMEMORY_FLAG_DATA, 'D'),
		DIRECT(JMemory.JMEMORY_FLAG_DIRECT, 'T'),
		JAVA_OWNED(JMemory.JMEMORY_FLAG_JAVA_OWNED, 'J'),
		PROXY(JMemory.JMEMORY_FLAG_PROXY, 'X'),
		READ(JMemory.JMEMORY_FLAG_READ, 'R'),
		REFERENCE(JMemory.JMEMORY_FLAG_REFERENCE, 'F'),
		WRITE(JMemory.JMEMORY_FLAG_WRITE, 'W'), 
		NO_PEERING(JMemory.JMEMORY_FLAG_NO_PEERING, 'N'), 
		LC_ATTACHED(JMemory.JMEMORY_FLAG_LC_ATTACHED, 'L'), 
		;
		
		public static void printFlagLegend() {
			for (Flag f : values()) {
				System.out.printf("%10s=%c 0x%04x\n", f.name(), f.letter, f.value);
			}
		}

		public static String toSummary(int flags) {
			StringBuilder b = new StringBuilder();
			for (Flag f : values()) {
				if ((flags & f.value) != 0) {
					b.append(f.letter);
				}
			}

			return b.toString();
		}

		private final char letter;

		private final int value;

		private Flag(int value, char letter) {
			this.value = value;
			this.letter = letter;

		}
	}

	/**
	 * Used in special memory allocation. Allows the user to specify the type
	 * allocation required of this memory object.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Type {

		/**
		 * Object is the owner of memory block which it allocated. This object is
		 * responsible for memory cleanup when its finalized.
		 */
		BLOCK(JMemory.JMEMORY_TYPE_BLOCK),

		/**
		 * Node type which maintains a reference to java objects. This memory node
		 * type replicates the functionality of java references but within jmemory
		 * management context. It provides a way to attach java references to any
		 * JMemory based object, generically. The lifespan of the JREF node is then
		 * tied to the lifespan of the node it is attached to.
		 */
		JREF(JMEMORY_TYPE_JREF),

		/**
		 * 
		 */
		PEER(JMEMORY_TYPE_PEER),

		/**
		 * Peered object is being created as a reference pointer and has no memory
		 * allocated on its own. It is expected that new object will be peered with
		 * exising memory location. The same concept as a native memory pointer,
		 * think void * in C.
		 * 
		 * @deprecated please use PEER instead
		 */
		POINTER(JMEMORY_TYPE_PEER), ;
		/**
		 * Converts a numerical type into enum type.
		 * 
		 * @param type
		 *          numerical memory node type
		 * @return enum type
		 */
		public static Type valueOf(int type) {
			switch (type) {
				case JMEMORY_TYPE_BLOCK:
					return BLOCK;

				case JMEMORY_TYPE_PEER:
					return PEER;

				case JMEMORY_TYPE_JREF:
					return JREF;

				default:
					return null;
			}
		}

		/**
		 * Value corresponding to JMEMORY_TYPE_* constants
		 */
		public final int value;

		private Type(int value) {
			this.value = value;
		}
	}

	private static final int JMEMORY_FLAG_ACTIVE = 0x0001;

	static final int JMEMORY_FLAG_BIG_ENDIAN = 0x0002;

	private static final int JMEMORY_FLAG_DATA = 0x004;

	private static final int JMEMORY_FLAG_DIRECT = 0x0008;

	private static final int JMEMORY_FLAG_JAVA_OWNED = 0x0010;

	private static final int JMEMORY_FLAG_PROXY = 0x0020;

	private static final int JMEMORY_FLAG_READ = 0x0040;

	private static final int JMEMORY_FLAG_REFERENCE = 0x0080;
	
	private static final int JMEMORY_FLAG_WRITE = 0x0100;

	private static final int JMEMORY_FLAG_NO_PEERING = 0x0200;
	
	private static final int JMEMORY_FLAG_LC_ATTACHED = 0x0400;
	
	private static final int JMEMORY_TYPE_BLOCK = 0;

	private static final int JMEMORY_TYPE_JREF = 2;

	private static final int JMEMORY_TYPE_PEER = 1;

	/**
	 * Name of the native library that wraps around libpcap and extensions
	 */
	public static final String JNETPCAP_LIBRARY_NAME = "jnetpcap";

	/**
	 * Convenience constant that is synonym as JMemory.Type.PEER. Since this type
	 * constant is used so often, it is made as a in-class constant to make it
	 * easier to access.
	 */
	public static final JMemory.Type PEER = JMemory.Type.PEER;

	/**
	 * Convenience constant that is synonym as JMemory.Type.POINTER. Since this
	 * type constant is used so often, it is made as a in-class constant to make
	 * it easier to access.
	 * 
	 * @deprecated please use JMemory.Type.PEER
	 */
	public static final JMemory.Type POINTER = JMemory.Type.PEER;
	
	/**
	 * Dynamic initialized used to keep the compiler from optimizing this.physical
	 * away.
	 */
	{
		physical = 0L;
	}

	/**
	 * Load the native library and initialize JNI method and class IDs.
	 */
	static {
		try {
			System.loadLibrary(JNETPCAP_LIBRARY_NAME);

			// Pcap.isInjectSupported();

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
	 * Used to lock read and write operation on the native memory we point to. The
	 * locks all locks for reading threads will not block unless there is a write
	 * lock as well. Initialized lazely.
	 */
	private ReadWriteLock lock;

	/**
	 * Physical address of the memory we can access. Even though this property
	 * is marked final, it is still modified from JNI which is the only place
	 * that is allowed to modify it. 
	 */
	private final long physical;

	/**
	 * Allocates this object in peering mode. This object may only be used to peer
	 * with other <code>JMemory</code> based objects. Using this object before
	 * it has been peered with another object will result in
	 * <code>NullPointerException</code> being thrown as none of this object
	 * properties are initialized or usable.
	 */
	protected JMemory() {
		this(Type.PEER);
	}

	/**
	 * @param src
	 */
	protected JMemory(ByteBuffer src) {
		this(src.limit() - src.position());

		transferFrom(src);
	}

	/**
	 * Allocates native memory and makes this object the owner and manager of that
	 * memory. Once an owner object is created, it may never be reused as a peer
	 * to another object. Only objects of
	 * 
	 * @param size
	 *          number of bytes to pre-allocate allocate
	 */
	protected JMemory(int size) {
		createBlockNode(size);
	}

	/**
	 * Performs a deep copy into a newly allocated memory block
	 * 
	 * @param src
	 */
	protected JMemory(JMemory src) {
		this(src.size());

		src.transferTo(this);
	}

	/**
	 * Allocates this object in peering mode. This object may only be used to peer
	 * with other <code>JMemory</code> based objects. Using this object before
	 * it has been peered with another object will result in
	 * <code>NullPointerException</code> being thrown as none of this object
	 * properties are initialized or usable.
	 * 
	 * @param type
	 *          only Type.POINTER is accepted by this constructor and all other
	 *          types will throw an IllegalArgumentException
	 * @throws IllegalArgumentException
	 *           if any other memory Type is supplied besides Type.POINTER
	 */
	protected JMemory(Type type) {

		switch (type) {

			case POINTER:
			case PEER:
				createPeerNode();
				break;

			case JREF:
				createJRefNode();
				break;

			case BLOCK:
				throw new IllegalArgumentException(
				    "block type nodes must created using "
				        + "constructor that takes memory size");

			default:
				throw new IllegalArgumentException("unsupported node type "
				    + jmemoryType());
		}
	}

	/**
	 * Checks if this peered object is initialized. This method throws
	 * IllegalStateException if not initialized and does not return any values.
	 * Its intended to as an assert mechanism
	 * 
	 * @throws IllegalStateException
	 *           if peered object is not initialized this unchecked exception will
	 *           be thrown, otherwise it will exit silently
	 */
	// public native void check() throws IllegalStateException;
	// protected void cleanup() {
	// reset();
	// }
	/**
	 * Create a block_t node with size bytes of data allocated.
	 * 
	 * @param size
	 *          number of bytes to allocate.
	 */
	private native void createBlockNode(int size);

	/**
	 * Create an inactive jref_t node
	 */
	private native void createJRefNode();

	/**
	 * Create an inactive peer_t node
	 */
	private native void createPeerNode();

	private final Object dataOwner() {

		switch (jmemoryType()) {
			case JMEMORY_TYPE_BLOCK:
				return this;

			case JMEMORY_TYPE_PEER:
				return (isActive()) ? jpeerJRef() : null;

			case JMEMORY_TYPE_JREF:
				return null; // JREF doesn't point at data, only holds a java reference
		}

		return null;
	}

	/**
	 * Default finalizer which checks if there is any memory to free up.
	 */
	@Override
	protected void finalize() {
		free();
	}

	/**
	 * Discards the memory node resources and memory. After this call, this object
	 * is no longer usable in any shape or form. This method can only be called
	 * from the finalizer of this object.
	 */
	private native void free();

	/**
	 * Checks if this peered object is initialized. This method does not throw any
	 * exceptions.
	 * 
	 * @return if initialized true is returned, otherwise false
	 */
	private final native boolean isActive();

	/**
	 * @return true or false
	 */
	public boolean isInitialized() {
		return isActive();
	}

	/**
	 * Checks if access to native memory is read-only.
	 * 
	 * @return true if its read-only
	 */
	public final boolean isReadonly() {
		final int flags = jmemoryFlags();
		return (jmemoryFlags() & (JMEMORY_FLAG_READ | JMEMORY_FLAG_WRITE)) != JMEMORY_FLAG_READ;
	}

	/**
	 * Returns defined flags assigned to this memory node. These flags have no
	 * meaning to <code>JMemory</code> class.
	 * 
	 * @return node's flags
	 */
	final native int jmemoryFlags();

	/**
	 * Sets memory node's flags.
	 * 
	 * @param flags
	 *          new flags
	 */
	final native void jmemoryFlags(int flags);

	/**
	 * Reads the jmemory_t.next field.
	 * 
	 * @return next node in a linked list of JMemory nodes
	 */

	private final native JMemory jmemoryNext();

	/**
	 * Reads the jmemory_t.type field.
	 * 
	 * @return returns numerical memory node type
	 */
	private final native int jmemoryType();

	/**
	 * Reads peer_t.jref field which holds a reference to the owner of the data we
	 * are pointing when this PEER node is active.
	 * 
	 * @return owner of the data block if node is active, otherwise null
	 */

	private final native Object jpeerJRef();

	/**
	 * Reads jref_t.jref field which holds a reference to a java object.
	 * 
	 * @return owner of the data block if node is active, otherwise null
	 */
	private final native Object jrefJRef();

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
	 * {@link #reset()} method to ensure that this object no longer references
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
	 * @throws PeeringException
	 *           if the specified memory offset and length have negative or out of
	 *           bounds of peer objects address space
	 */
	protected native int peer(JMemory peer, int offset, int length);

	/**
	 * Returns a thread lock on the underlying native memory which this object is
	 * accessing. This operation only works for JMemory based memory managment and
	 * will not work if this object is peered with a ByteBuffer object.Here is a
	 * typical example
	 * 
	 * <pre>
	 * PcapPacket packet = ...; // from some source
	 * Ip4 ip = new Ip4();
	 * ReadWriteLock l = packet.readWriteLock();
	 * 
	 * 
	 * Lock readLock = l.readLock();
	 * readLock.lock();
	 * try {
	 *   if (packet.hasHeader(ip)) {
	 *     // Do read logic
	 *   }
	 * } finally {
	 *   readLock.unlock();
	 * }
	 * </pre>
	 * 
	 * while another thread may be trying to write to the same packet
	 * 
	 * <pre>
	 * PcapPacket packet = ...; // from some source
	 * Ip4 ip = new Ip4();
	 * ReadWriteLock l = packet.readWriteLock();
	 * 
	 * 
	 * Lock writeLock = l.writeLock();
	 * try {
	 *   if (packet.hasHeader(ip)) {
	 *     // Do write logic
	 *   }
	 *   
	 *   packet.scan(); // Rescan packet since we changed its content
	 * } finally {
	 *   writeLock.unlock();
	 * }
	 * </pre>
	 * 
	 * Both read and write threads will be properly synchronized while accessing
	 * the same packet data. This implementation of read and write lock will give
	 * preferance to a write lock when multiple read and write locks are waiting
	 * for access to object's data.
	 * 
	 * @return a read-write lock
	 * @throws UnsupportedOperationException
	 *           thrown when this memory object is peered with a ByteBuffer object
	 *           which is the owner of the native memory. ReadWrite locks can not
	 *           be generated for that type of peered objects and will throw this
	 *           exception.
	 */
	public ReadWriteLock readWriteLock() throws UnsupportedOperationException {
		if (isActive() == false) {
			throw new NullPointerException();
		}

		if (jmemoryType() == JMEMORY_TYPE_PEER) {
			if (dataOwner() instanceof JMemory) {
				return ((JMemory) dataOwner()).readWriteLock();
			} else {
				throw new UnsupportedOperationException(
				    "readWriteLock can not be acquired for peered "
				        + "JMemory to ByteBuffer object");
			}

		} else {
			if (this.lock == null) {
				this.lock = new ReentrantReadWriteLock();
			}

			return lock;
		}
	}

	/**
	 * Do a soft reset on the underlying memory node. Reset will free up any
	 * currently allocated resources, with one exception. Block nodes can not be
	 * freed up. They can only be deactivated, which will cause the node to be
	 * quickly dereferenced by any peers and eventually discarded by java GC
	 * mechanism.
	 */
	protected native void reset();

	protected final void setReadonly(boolean state) {
		jmemoryFlags(jmemoryFlags() & ~JMEMORY_FLAG_WRITE);
	}

	/**
	 * Returns the size of the memory block that this peered structure is point
	 * to. This object does not neccessarily have to be the owner of the memory
	 * block and could simply be a portion of the over all memory block. Also the
	 * returned size does not include jmemory managment overhead.
	 * 
	 * @return number of byte currently allocated
	 */
	public native int size();

	/**
	 * Returns an opaque object suitable for usage in java synchronized statement
	 * for locking access to underlying native memory. Unlike
	 * {@link #readWriteLock()} method, this object returns a handle for all types
	 * of memory including ByteBuffer.
	 * <p>
	 * Here is a typical usage where 2 threads (1 read and 1 write) threads need
	 * to be synchronized to prevent concurrent modification to occur. The first
	 * is the reader thread:
	 * 
	 * <pre>
	 * PcapPacket packet = ...; // From some where 
	 * Ip4 ip = new Ip4(); 
	 * Object lock = packet.syncHandle(); 
	 * synchronized(lock) { 
	 *   if (packet.hasHeader(ip)) { 
	 *     // Do read logic 
	 *   } 
	 * }
	 * </pre>
	 * 
	 * while the second is the writer thread:
	 * 
	 * <pre>
	 * PcapPacket packet = ...; // From some where 
	 * Ip4 ip = new Ip4(); 
	 * Object lock = packet.syncHandle(); 
	 * synchronized(lock) { 
	 *   if (packet.hasHeader(ip)) { 
	 *     // Do write logic 
	 *   } 
	 *   
	 *   packet.scan(); // rescan since we changed packet contents 
	 * }
	 * </pre>
	 * 
	 * </p>
	 * 
	 * @return an opaque handle suitable for usage in synchronized statement. This
	 *         method never returns null.
	 */
	public Object syncHandle() {

		if (isInitialized() == false) {
			throw new NullPointerException();
		}

		return (jmemoryType() == JMEMORY_TYPE_PEER) ? dataOwner() : this;
	}

	/**
	 * Returns a debug string about this JMemory state. Example:
	 * 
	 * <pre>
	 * JMemory@b052fa8: size=1506, owner=nio.JMemoryPool$Block.class(size=10240/offset=4064)
	 * </pre>
	 * 
	 * <ul>
	 * <li>hex nuber, is physical memory location
	 * <li>size = number of bytes of this memory object
	 * <li>owner = the class name of the object that owns the physical memory
	 * <li>isOwner = if true, means that this object is the owner of physical
	 * memory
	 * <li>size in parenthesis = the size of the physical memory allocated by the
	 * owner
	 * <li>offset in parenthesis = the offset into the physical memory block of
	 * this memory object
	 * </ul>
	 * 
	 * @return a summary string describing the state of this memory object
	 */
	public String toDebugString() {
		if (isActive() == false) {
			return super.toString();
		}
		
		final StringBuilder b = new StringBuilder();
		final String t = "JMemory:" + Type.valueOf(jmemoryType()) + ":";

		b.append(t).append(" this=").append(this.getClass().getSimpleName());
		b.append('@').append(Long.toHexString(physical));
		b.append(", ");

		b.append(" flags=[").append(Flag.toSummary(jmemoryFlags())).append(']');
		b.append("(0x").append(Integer.toHexString(jmemoryFlags())).append(')');
		b.append(", ");

		Object dataOwner = dataOwner();

		switch (jmemoryType()) {
			case JMEMORY_TYPE_BLOCK:
				if (isActive()) {
					b.append(" size=").append(size());
				}
				break;

			case JMEMORY_TYPE_PEER:
				if (isActive()) {
					b.append(" size=").append(size());
					b.append(", ");
					b.append(" data=").append(size());

					if (dataOwner != null) {
						b.append(", ");
						b.append(" owner=").append(dataOwner.toString());
					}
				}
				break;

		}

		return b.toString();
	}

	/**
	 * A debug method, similar to toString() which converts the contents of the
	 * memory to textual hexdump.
	 * 
	 * @return multi-line hexdump of the entire memory region
	 */
	public String toHexdump() {
		if (isInitialized() == false) {
			return "not initialized";
		}

		JBuffer b = new JBuffer(Type.PEER);
		b.peer(this);

		return FormatUtils.hexdumpCombined(b.getByteArray(0, size()), 0, 0, true,
		    true, true);
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
		length = (length < size()) ? length : size();
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
		return transferTo(dst, 0, size());
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
		return transferTo(dst, 0, size(), 0);
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