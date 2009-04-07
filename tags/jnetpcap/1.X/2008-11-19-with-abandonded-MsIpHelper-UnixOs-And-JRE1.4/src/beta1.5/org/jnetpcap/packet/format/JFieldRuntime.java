package org.jnetpcap.packet.format;

import org.jnetpcap.packet.JHeader;

/**
 * Interface which provides runtime field information
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JFieldRuntime<H extends JHeader, V> {
	public boolean hasField(H header);
	
	public V value(H header);
	
	public int getOffset();
	
	public int getLength();
	
	/**
	 * @return the mask
	 */
	public int getMask();
	
	public String valueDescription(H header);

}