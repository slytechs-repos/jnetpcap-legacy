/**
 * 
 */
package org.jnetpcap.nio;

/**
 * Allows resources to be deterministicly reclaimed.
 * 
 * @author markbe
 * 
 */
public interface Disposable {

	/**
	 * The objects underlying resources are reclaimed immediately.
	 */
	public void dispose();

}
