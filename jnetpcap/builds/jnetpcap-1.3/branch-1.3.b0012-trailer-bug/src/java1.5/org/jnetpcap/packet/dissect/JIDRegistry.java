/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.packet.dissect;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JIDRegistry {

	private final int mask;

	private final int size;

	private final int width;

	/**
	 * Initializes the ID registry to manage ID of certain bit-size. The size is
	 * the number of bits to use for width of unique index.
	 * 
	 * @param width
	 *          size of registry in bits
	 */
	public JIDRegistry(int width) {
		this.width = width;
		this.size = 1 << width;
		this.mask = createMask(size);
	}

	/**
	 * 
	 * @param size
	 * @return
	 */
	private int createMask(int size) {
		return size - 1;
	}

	/**
	 * 
	 * @param id
	 * @return
	 */
	private int flatten(int id) {
		int f = 0;
		for (; id > (1 << width); id >>= width) {
			f += id & mask;
		}

		return f;
	}

	/**
	 * @param id
	 * @return
	 */
	public int map(int id) {
		return flatten(id);
	}
	
	/**
	 * @param str
	 * @return
	 */
	public int map(String str) {
		return map(str.hashCode());
	}

}
