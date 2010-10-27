/**
 * 
 */
package org.jnetpcap.nio;

/**
 * @author markbe
 * 
 */
public class JMemoryReference extends DisposableReference {

	/**
	 * Address is modified by JNI, even though it is marked final. This prevents
	 * anyone else from changing it, except the JNI code reponsible for management
	 * of this object. This value is only changed during the construction of the
	 * object and during the destroy call.
	 */
	long address;
	long size;

	/**
	 * @param referant
	 */
	public JMemoryReference(Object referant, long address, long size) {
		super(referant);
		this.address = address;
		this.size = size;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.Disposable#dispose()
	 */
	@Override
	public void dispose() {
		disposeNative(size);
	}

	/**
	 * Does a native memory cleanup
	 */
	protected void disposeNative(long size) {
		disposeNative0(address, size);
	}
	
	private native void disposeNative0(long address, long size);

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.DisposableReference#remove()
	 */
	@Override
	public void remove() {
		address = 0L;
		size = 0L;
		super.remove();
	}

}
