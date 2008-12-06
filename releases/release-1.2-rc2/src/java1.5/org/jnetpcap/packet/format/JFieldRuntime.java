package org.jnetpcap.packet.format;

import org.jnetpcap.packet.JHeader;

/**
 * Interface which provides runtime field information. Runtime information is
 * suppolied to a field so that it can do special processing with it. Every type
 * of field is supplied with runtime information so that it can properly
 * determine the actual value of the field within a header.
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