/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.nio;

import java.nio.ByteBuffer;

// TODO: Auto-generated Javadoc
/**
 * The Class JStruct.
 */
public class JStruct
    extends
    JMemory {

	/** The struct name. */
	private final String structName;

	/**
	 * Instantiates a new j struct.
	 * 
	 * @param structName
	 *          the struct name
	 * @param type
	 *          the type
	 */
	public JStruct(String structName, Type type) {
		super(type);
		this.structName = structName;
	}

	/**
	 * Instantiates a new j struct.
	 * 
	 * @param structName
	 *          the struct name
	 * @param peer
	 *          the peer
	 */
	public JStruct(String structName, ByteBuffer peer) {
		super(peer);
		this.structName = structName;
	}

	/**
	 * Instantiates a new j struct.
	 * 
	 * @param structName
	 *          the struct name
	 * @param size
	 *          the size
	 */
	public JStruct(String structName, int size) {
		super(size);
		this.structName = structName;
	}

	/**
	 * Instantiates a new j struct.
	 * 
	 * @param structName
	 *          the struct name
	 * @param peer
	 *          the peer
	 */
	public JStruct(String structName, JMemory peer) {
		super(peer);
		this.structName = structName;
	}

	/**
	 * Gets the struct name.
	 * 
	 * @return the struct name
	 */
	public final String getStructName() {
		return this.structName;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return "struct " + structName;
	}
}
