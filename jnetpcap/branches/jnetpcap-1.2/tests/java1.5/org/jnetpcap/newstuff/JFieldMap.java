/**
 * Copyright (C) 2008 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jnetpcap.newstuff;

import java.util.Arrays;
import java.util.Comparator;
import java.util.Map;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.structure.JField;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class JFieldMap {
	private Map<String, JField> fieldMap;

	protected boolean hasField(Enum<? extends Enum<?>> field) {
		return fieldMap.containsKey(field);
	}

	protected String fieldDescription(Enum<? extends Enum<?>> field, final JHeader header) {
		return fieldMap.get(field).getValueDescription(header);
	}

	protected int fieldLength(Enum<? extends Enum<?>> field, final JHeader header) {
		return fieldMap.get(field).getLength(header);
	}

	protected int fieldOffset(Enum<? extends Enum<?>> field, final JHeader header) {
		return fieldMap.get(field).getOffset(header);
	}

	protected Object fieldValue(Enum<? extends Enum<?>> field, final JHeader header) {
		return fieldMap.get(field.name()).getValue(header);
	}

	protected <V> V fieldValue(Class<V> c, Enum<? extends Enum<?>> field, final JHeader header) {
		return fieldMap.get(field).getValue(c, header);
	}

	public String[] fieldArray(final JHeader header) {

		final String[] r = fieldMap.keySet().toArray(new String[fieldMap.size()]);

		Arrays.sort(r, new Comparator<String>() {

			public int compare(String o1, String o2) {
				return fieldMap.get(o1).getOffset(header)
				    - fieldMap.get(o2).getOffset(header);
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
