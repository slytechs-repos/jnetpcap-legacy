/**
 * 
 */
package org.jnetpcap.packet;

import org.jnetpcap.nio.JMemoryReference;

/**
 * @author markbe
 * 
 */
public class JScannerReference extends JMemoryReference {

	/**
	 * @param referant
	 * @param address
	 */
	public JScannerReference(Object referant, long address) {
		super(referant, address);
	}

	/**
	 * Clean up the scanner_t structure and release any held resources. For one
	 * all the JHeaderScanners that are kept as global references need to be
	 * released.
	 */
	@Override
	public native void dispose();

}
