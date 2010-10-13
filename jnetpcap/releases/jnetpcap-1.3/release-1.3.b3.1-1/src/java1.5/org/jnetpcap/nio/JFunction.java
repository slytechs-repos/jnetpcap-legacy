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
package org.jnetpcap.nio;

/**
 * A special memory peer to a function pointer
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JFunction
    extends
    JMemory {

	private final String name;

	/**
	 * Creates an empty function object suitable for peering
	 * 
	 * @param name
	 *          name of this function
	 */
	public JFunction(String name) {
		super(Type.POINTER);
		this.name = name;
	}

	/**
	 * @return the name
	 */
	public final String getName() {
		return this.name;
	}
}
