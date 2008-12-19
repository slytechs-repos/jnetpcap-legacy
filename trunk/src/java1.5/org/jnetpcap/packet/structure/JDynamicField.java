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
package org.jnetpcap.packet.structure;

import org.jnetpcap.packet.JHeader;

/**
 * A header field that doesn't have constant offset into a header. Dynamic field
 * specifics have to be determined at runtime after a header is bound to a
 * packet. Flags and other conditions within the field determine if a field
 * exists at all in the header and what offset and length it is.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @param <H>
 * @param <V>
 */
public abstract class JDynamicField<H extends JHeader, V> implements
    JFieldRuntime<H, V> {

	private int offset;

	private int length;

	public JDynamicField() {
		// Empty
	}

	/**
	 * Creates a dynamic field, one that doesn't have a static offset or length
	 * 
	 * @param offset
	 *          offset into the header in bits
	 */
	public JDynamicField(int offset) {
		this.offset = offset;
	}

	/**
	 * Gets the offset of this field
	 * 
	 * @return the offset in bits
	 */
	public final int getOffset(H header) {
		return this.offset;
	}

	/**
	 * Sets the offset of this field in bits
	 * 
	 * @param offset
	 *          the offset to set
	 */
	public final void setOffset(int offset) {
		this.offset = offset;
	}

	/**
	 * Length of this field in bits
	 * 
	 * @return the length
	 */
	public final int getLength(H header) {
		return this.length;
	}

	/**
	 * Sets the length of this field in bits
	 * 
	 * @param length
	 *          the length to set
	 */
	public final void setLength(int length) {
		this.length = length;
	}

	/**
	 * Checks if this field exists in the header
	 * 
	 * @param header
	 *          header to check for
	 */
	public boolean hasField(H header) {
		return true;
	}

	/**
	 * A bitfield mask. The bits that are set in this mask will be the ones marked
	 * as either 0 or 1, all others will be ignored
	 * 
	 * @return bitfield
	 * @see org.jnetpcap.packet.structure.JFieldRuntime#getMask(JHeader)
	 */
	public int getMask(H header) {
		return 0;
	}

	/**
	 * A custom description of this field. This method is ment to be overriden by
	 * subclass field
	 * 
	 * @return a string describing the field value
	 * @see org.jnetpcap.packet.structure.JFieldRuntime#valueDescription(org.jnetpcap.packet.JHeader)
	 */
	public String valueDescription(H header) {
		return null;
	}

	/**
	 * Sets the bitfield mask
	 * 
	 * @param mask
	 *          the mask to set
	 */
	public final void setMask(int mask) {
	}

}