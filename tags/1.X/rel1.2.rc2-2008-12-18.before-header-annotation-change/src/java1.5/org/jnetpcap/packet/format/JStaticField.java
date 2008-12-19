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
 * A header field object used by formatters to describe formatting options that
 * a formatter should use. Static fields have constant offset and length within
 * the header unlike JDynamicFields which have to determine both of those
 * properties at runtime.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JStaticField<H extends JHeader, V> implements
    JFieldRuntime<H, V> {

	private final int offset;

	private final int length;

	private final int mask;

	public JStaticField(int offset, int length) {
		this(offset, length, 0);
	}

	/**
	 * @param offset
	 *          into the header in bytes
	 * @param length
	 *          length of the field in bits
	 */
	public JStaticField(int offset, int length, int mask) {
		this.offset = offset;
		this.length = length;
		this.mask = mask;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JField.JFieldRuntime#hasField(org.jnetpcap.packet.JHeader)
	 */
	public boolean hasField(H header) {
		return true;
	}

	/**
	 * Gets the offset into the header of the field in bytes
	 * 
	 * @return the offset in bytes
	 */
	public final int getOffset(H header) {
		return this.offset;
	}

	/**
	 * Gets the length of the field in bits
	 * 
	 * @return the length in bits
	 */
	public final int getLength(H header) {
		return this.length;
	}

	/**
	 * @return the mask
	 */
	public final int getMask(H header) {
		return this.mask;
	}

	public String valueDescription(H header) {
		return null;
	}

}