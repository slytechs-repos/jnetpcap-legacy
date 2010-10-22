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
	{
		address = 0L;
	}

	/**
	 * @param referant
	 */
	public JMemoryReference(Object referant, long address) {
		super(referant);
		this.address = address;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.Disposable#dispose()
	 */
	@Override
	public void dispose() {
		disposeNative();
	}

	/**
	 * Does a native memory cleanup
	 */
	protected native void disposeNative();

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.DisposableReference#remove()
	 */
	@Override
	public void remove() {
		address = 0L;
		super.remove();
	}

}
