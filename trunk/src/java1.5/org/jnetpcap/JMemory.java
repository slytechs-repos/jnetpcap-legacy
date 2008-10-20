package org.jnetpcap;

import java.nio.ByteBuffer;

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
	 * Number of byte currently allocated
	 */
	private int size;

	/**
	 * No memory pre-allocation constructor
	 */
	public JMemory() {
		this.size = 0;
	}

	/**
	 * Pre-allocates memory for any structures the subclass may need to use.
	 * 
	 * @param size
	 *          number of bytes to pre-allocate allocate
	 */
	public JMemory(int size) {
		this.size = size;
		this.owner = true;
		allocate(size);
	}

	public JMemory(JMemory peer) {
		peer(peer);
	}

	/**
	 * Returns the size of the memory block that this peered structure is point
	 * to. This object does not neccessarily have to be the owner of the memory
	 * block and could simply be a portion of the over all memory block.
	 * 
	 * @return number of byte currently allocated
	 */
	public int size() {
		return size;
	}

	private static native void initIDs();

	static {
		try {
			Pcap.isInjectSupported(); // Force load of the library
			initIDs();
		} catch (Exception e) {
			System.err.println(e.getClass().getName() + ": "
			    + e.getLocalizedMessage());
			throw new ExceptionInInitializerError(e);
		}
	}

	/**
	 * Physical address of the peered structure. This variable is modified outside
	 * java space as C structures are bound to it. Subclasses implement methods
	 * and fields that understand the exact structure.
	 */
	private volatile long physical;

	/**
	 * Specifies if this object owns the allocated memory. Using JMemory.allocate()
	 * automatically makes the object owner of the allocated memory block.
	 * Otherwise it is assumed that the {@link #physical} memory pointer is
	 * referencing a memory block not owned by this object, and therefore will not
	 * try and deallocate that memory upon cleanup.
	 * <p>
	 * Remember that physical field is set from within a native call and any
	 * object subclassing JMemory can be made to reference any memory location
	 * including another JMemory object's allocated memory or anywhere for that
	 * matter.
	 * </p>
	 */
	private volatile boolean owner = false;

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
	 * Checks if this peered object is initialized. This method does not throw any
	 * exceptions.
	 * 
	 * @return if initialized true is returned, otherwise false
	 */
	public boolean isInitialized() {
		return physical != 0;
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
	public void check() throws IllegalStateException {
		if (physical == 0) {
			return;
		}

		throw new IllegalStateException(
		    "peered object not synchronized with native structure");
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
	public native void cleanup();

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
	 * @see ByteBuffer#isDirect()
	 */
	public native void peer(ByteBuffer peer);

	/**
	 * Peers the peer structure with this instance. The physical memory that the
	 * peer object points to is set to this instance. The owner flag is not copied
	 * and peer remains at the same state as it did before. This instance does not
	 * become the owner of the memory.
	 * 
	 * @param peer
	 *          the object whose allocated native memory we want to peer with
	 */
	public void peer(JMemory peer) {
		finalized(); // Clean up any memory we own before we give it up

		this.physical = peer.physical;
		this.size = peer.size;

		/*
		 * For specific reasons, we can never be the owner of the peered structure.
		 * The owner should remain the object that initially created or was created
		 * to manage the physical memory. The reasons are as follows: <ul> <li>
		 * Memory could be a revolving buffer <li> Memory allocation could have been
		 * complex with sub structures that need to be deallocated <li> The src
		 * object may have been passed around and references stored to it elsewhere.
		 * If we are GCed before src and we free up the memory the original src
		 * object would become unstable </ul>
		 */
		this.owner = false;
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
	public void peer(JMemory peer, int offset, int length)
	    throws IndexOutOfBoundsException {
		if (offset < 0 || length < 0 || offset + length > size) {
			throw new IllegalArgumentException(
			    "Invalid [offset,offset + length) range.");
		}

		finalized(); // Clean up any memory we own before we give it up

		this.physical = peer.physical + offset;
		this.size = length;

		/*
		 * For specific reasons, we can never be the owner of the peered structure.
		 * The owner should remain the object that initially created or was created
		 * to manage the physical memory. The reasons are as follows: <ul> <li>
		 * Memory could be a revolving buffer <li> Memory allocation could have been
		 * complex with sub structures that need to be deallocated <li> The src
		 * object may have been passed around and references stored to it elsewhere.
		 * If we are GCed before src and we free up the memory the original src
		 * object would become unstable </ul>
		 */
		this.owner = false;

	}

	/**
	 * Default finalizer which checks if there is any memory to free up.
	 */
	protected void finalized() {
		if (physical != 0L && owner) {
			cleanup();
		}
	}
}