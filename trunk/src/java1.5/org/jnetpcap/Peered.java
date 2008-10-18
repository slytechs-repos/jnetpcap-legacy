package org.jnetpcap;

/**
 * A base class for all other PEERED classes to native c structures. The class
 * only contains the physical address of the native C structure. The class also
 * contains a couple of convenience methods for allocating memory for the
 * structure to be peered as well as doing cleanup and freeing up that memory
 * when object is finalized().
 * 
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class Peered {

	/**
	 * Number of byte currently allocated
	 */
	private int size;

	/**
	 * No memory pre-allocation constructor
	 */
	public Peered() {
		this.size = 0;
	}

	/**
	 * Pre-allocates memory for any structures the subclass may need to use.
	 * 
	 * @param size
	 *          number of bytes to pre-allocate allocate
	 */
	public Peered(int size) {
		this.size = size;
		this.owner = true;
		allocate(size);
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
		Pcap.isInjectSupported(); // Force load of the library
		initIDs();
	}

	/**
	 * Physical address of the peered structure. This variable is modified outside
	 * java space as C structures are bound to it. Subclasses implement methods
	 * and fields that understand the exact structure.
	 */
	private volatile long physical;

	/**
	 * Specifies if this object owns the allocated memory. Using Peered.allocate()
	 * automatically makes the object owner of the allocated memory block.
	 * Otherwise it is assumed that the {@link #physical} memory pointer is
	 * referencing a memory block not owned by this object, and therefore will not
	 * try and deallocate that memory upon cleanup.
	 * <p>
	 * Remember that physical field is set from within a native call and any
	 * object subclassing Peered can be made to reference any memory location
	 * including another Peered object's allocated memory or anywhere for that
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
	 * Called by finalizer to clean up and release any allocated memory. This
	 * method should be overriden if the allocated memory is not simply a single
	 * memory block and something more complex.
	 */
	protected native void cleanup();

	/**
	 * Peers the src structure with this instance. The physical memory that the
	 * src peered object points to is set to this instance. The owner flag is not
	 * copied and src remains at the same state as it did before. This instance is
	 * not the owner of the memory
	 * 
	 * @param src
	 */
	protected void peer(Peered src) {
		finalized(); // Clean up any memory we own before we give it up
		
		this.physical = src.physical;
		this.size = src.size;

		/*
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