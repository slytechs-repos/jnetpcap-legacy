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
	 * No memory pre-allocation constructor
	 */
	public Peered() {
		// Empty
	}

	/**
	 * Pre-allocates memory for any structures the subclass may need to use.
	 * 
	 * @param size
	 *          number of bytes to pre-allocate allocate
	 */
	public Peered(int size) {
		allocate(size);
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
	 * Default finalizer which checks if there is any memory to free up.
	 */
	protected void finalized() {
		if (physical != 0L) {
			cleanup();
		}
	}
}