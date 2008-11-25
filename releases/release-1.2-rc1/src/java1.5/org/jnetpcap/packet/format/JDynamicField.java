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
package org.jnetpcap.packet.format;

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
	 * @param i
	 */
	public JDynamicField(int offset) {
		this.offset = offset;
	}

	/**
	 * @return the offset
	 */
	public final int getOffset() {
		return this.offset;
	}

	/**
	 * @param offset
	 *          the offset to set
	 */
	public final void setOffset(int offset) {
		this.offset = offset;
	}

	/**
	 * @return the length
	 */
	public final int getLength() {
		return this.length;
	}

	/**
	 * @param length
	 *          the length to set
	 */
	public final void setLength(int length) {
		this.length = length;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JField.JFieldRuntime#hasField(org.jnetpcap.packet.JHeader)
	 */
	public boolean hasField(H header) {
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#getMask()
	 */
	public int getMask() {
		return 0;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFieldRuntime#valueDescription(org.jnetpcap.packet.JHeader)
	 */
	public String valueDescription(H header) {
		return null;
	}

	/**
	 * @param mask
	 *          the mask to set
	 */
	public final void setMask(int mask) {
	}

}