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
package org.jnetpcap.nio;

import java.nio.ByteBuffer;

import org.jnetpcap.nio.JMemory.Type;

/**
 * Base class for peered pure structure classes. This class purposely does not
 * extend JBuffer to allow structure fields to be read out generically as that
 * is not portable accross platforms and architectures. Most structures are
 * written specifically for local machine architecture and OS, unlike network
 * protocols which can be usually read by use of generic <code>JBuffer</code>.
 * Therefore as a general requirement each JStruct has to implement its own
 * native methods to read and write fields into the structure.
 * <p>
 * As a convention, each subclass of JStruct implements a static method
 * <code>sizeof()</code> which returns the length of the structure, if the
 * structure is static in length. If not, then no requirement to implement the
 * static method <code>sizeof()</code> exists.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JStruct
    extends JMemory {

	/**
	 * Name of the native structure
	 */
	private final String structName;

	/**
	 * @param type TODO
	 * 
	 */
	public JStruct(String structName, Type type) {
		super(type);
		this.structName = structName;
	}

	/**
	 * @param peer
	 */
	public JStruct(String structName, ByteBuffer peer) {
		super(peer);
		this.structName = structName;
	}

	/**
	 * @param size
	 */
	public JStruct(String structName, int size) {
		super(size);
		this.structName = structName;
	}

	/**
	 * @param peer
	 */
	public JStruct(String structName, JMemory peer) {
		super(peer);
		this.structName = structName;
	}

	public final String getStructName() {
		return this.structName;
	}

	public String toString() {
		return "struct " + structName;
	}
}
