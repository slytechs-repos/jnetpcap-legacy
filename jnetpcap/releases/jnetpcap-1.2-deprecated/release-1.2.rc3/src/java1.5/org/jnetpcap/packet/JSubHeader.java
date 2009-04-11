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
package org.jnetpcap.packet;

import org.jnetpcap.packet.structure.JField;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JSubHeader<T extends JHeader>
    extends JHeader {

	private int length;

	private int offset;

	private JHeader parent;

	public JSubHeader() {
		super();
	}

	/**
	 * @param id
	 * @param fields
	 * @param name
	 * @param nicname
	 */
	public JSubHeader(int id, JField[] fields, String name, String nicname) {
		super(id, fields, name, nicname);
	}

	/**
	 * @param id
	 * @param fields
	 * @param name
	 */
	public JSubHeader(int id, JField[] fields, String name) {
		super(id, fields, name);
	}

	/**
	 * @param id
	 * @param name
	 * @param nicname
	 */
	public JSubHeader(int id, String name, String nicname) {
		super(id, name, nicname);
	}

	/**
	 * @param id
	 * @param name
	 */
	public JSubHeader(int id, String name) {
		super(id, name);
	}

	/**
	 * @param state
	 * @param fields
	 * @param name
	 * @param nicname
	 */
	public JSubHeader(State state, JField[] fields, String name, String nicname) {
		super(state, fields, name, nicname);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JHeader#getLength()
	 */
	@Override
	public int getLength() {
		return length;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JHeader#getOffset()
	 */
	@Override
	public int getOffset() {
		return offset;
	}

	/**
	 * @param offset
	 */
	public void setOffset(int offset) {
		this.offset = offset;
	}

	/**
	 * @param length
	 */
	public void setLength(int length) {
		this.length = length;
	}

	public void setParent(JHeader parent) {
		this.parent = parent;
	}

	public JHeader getParent() {
		return this.parent;
	}

}
