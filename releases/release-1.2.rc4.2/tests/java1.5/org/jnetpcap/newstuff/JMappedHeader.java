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
package org.jnetpcap.newstuff;

import java.util.Arrays;
import java.util.Comparator;
import java.util.Map;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.structure.JField;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JMappedHeader
    extends JHeader {

	/**
	 * 
	 */
	public JMappedHeader() {
	}

	/**
	 * @param protocol
	 */
	public JMappedHeader(JProtocol protocol) {
		super(protocol);
	}

	/**
	 * @param id
	 * @param fields
	 * @param name
	 */
	public JMappedHeader(int id, JField[] fields, String name) {
		super(id, fields, name);
	}

	/**
	 * @param id
	 * @param fields
	 * @param name
	 * @param nicname
	 */
	public JMappedHeader(int id, JField[] fields, String name, String nicname) {
		super(id, fields, name, nicname);
	}

	/**
	 * @param id
	 * @param name
	 */
	public JMappedHeader(int id, String name) {
		super(id, name);
	}

	/**
	 * @param id
	 * @param name
	 * @param nicname
	 */
	public JMappedHeader(int id, String name, String nicname) {
		super(id, name, nicname);
	}

	/**
	 * @param state
	 * @param fields
	 * @param name
	 * @param nicname
	 */
	public JMappedHeader(State state, JField[] fields, String name, String nicname) {
		super(state, fields, name, nicname);
	}

	private Map<String, JField> fieldMap;

	protected boolean hasField(Enum<? extends Enum<?>> field) {
		return fieldMap.containsKey(field);
	}

	protected String fieldDescription(Enum<? extends Enum<?>> field) {
		return fieldMap.get(field).getValueDescription(this);
	}

	protected int fieldLength(Enum<? extends Enum<?>> field) {
		return fieldMap.get(field).getLength(this);
	}

	protected int fieldOffset(Enum<? extends Enum<?>> field) {
		return fieldMap.get(field).getOffset(this);
	}

	protected Object fieldValue(Enum<? extends Enum<?>> field) {
		return fieldMap.get(field.name()).getValue(this);
	}

	protected <V> V fieldValue(Class<V> c, Enum<? extends Enum<?>> field) {
		return fieldMap.get(field).getValue(c, this);
	}

	public String[] fieldArray() {

		final String[] r = fieldMap.keySet().toArray(new String[fieldMap.size()]);

		Arrays.sort(r, new Comparator<String>() {

			public int compare(String o1, String o2) {
				return fieldMap.get(o1).getOffset(JMappedHeader.this)
				    - fieldMap.get(o2).getOffset(JMappedHeader.this);
			}

		});

		return r;
	}
	
	/**
	 * @param name
	 * @param value
	 * @param offset
	 * @param length
	 */
	public void addField(
	    Enum<? extends Enum<?>> field,
	    String value,
	    int offset) {
		addField(field, value, offset, value.length());
	}

	/**
	 * @param name
	 * @param value
	 * @param offset
	 * @param length
	 */
	public void addField(
	    Enum<? extends Enum<?>> field,
	    String value,
	    int offset,
	    int length) {
		this.fieldMap.put(field.name(), null);
	}

	/**
	 * @param name
	 * @param value
	 * @param offset
	 * @param length
	 */
	public void addField(String name, String value, int offset, int length) {
		this.fieldMap.put(name, null);
	}

	/**
	 * 
	 */
	public void clearFields() {
		this.fieldMap.clear();
	}
}
