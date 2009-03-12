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

import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;

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

	private static class Entry {

		private final String description;

		private final String display;

		private final int length;

		private final int offset;

		private final Object value;

		/**
		 * @param value
		 * @param offset
		 * @param length
		 * @param description
		 */
		public Entry(Object value, int offset, int length, String display,
		    String description) {
			this.value = value;
			this.offset = offset;
			this.length = length;
			this.display = display;
			this.description = description;
		}

		/**
		 * @param mappedHeader
		 * @return
		 */
		public String getValueDescription(JHeader mappedHeader) {
			return description;
		}

		/**
		 * @param mappedHeader
		 * @return
		 */
		public int getLength(JMappedHeader mappedHeader) {
			return length;
		}

		public String getDisplay(JMappedHeader mappedHeader) {
			return display;
		}

		/**
		 * @param mappedHeader
		 * @return
		 */
		public int getOffset(JMappedHeader mappedHeader) {
			return offset;
		}

		/**
		 * @param mappedHeader
		 * @return
		 */
		public Object getValue(JMappedHeader mappedHeader) {
			return value;
		}

		@SuppressWarnings("unchecked")
		public <V> V getValue(Class<V> c, JMappedHeader mappedHeader) {
			return (V) value;
		}

	}

	private final Map<String, Entry> fieldMap = new HashMap<String, Entry>(50);

	protected boolean hasField(Enum<? extends Enum<?>> field) {
		return fieldMap.containsKey(map(field));
	}

	@Dynamic(Field.Property.CHECK)
	protected boolean hasField(String field) {
		return fieldMap.containsKey(field);
	}

	protected String fieldDescription(Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getValueDescription(this);
	}

	@Dynamic(Field.Property.DESCRIPTION)
	protected String fieldDescription(String field) {
		return fieldMap.get(map(field)).getValueDescription(this);
	}

	protected String fieldDisplay(Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getDisplay(this);
	}

	@Dynamic(Field.Property.DISPLAY)
	protected String fieldDisplay(String field) {
		return fieldMap.get(map(field)).getDisplay(this);
	}

	protected int fieldLength(Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getLength(this);
	}

	@Dynamic(Field.Property.LENGTH)
	protected int fieldLength(String field) {
		return fieldMap.get(map(field)).getLength(this);
	}

	protected int fieldOffset(Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getOffset(this);
	}
	
	protected String map(Enum<? extends Enum<?>> field) {
		String s = field.name().replace('_', '-');
//		System.out.printf("JMappedHeader::map(%s)=%s\n", field.name(), s);
		return s;
	}
	
	protected String map(String field) {
		String s = field;
//		System.out.printf("JMappedHeader::map(%s)=%s\n", field, s);
		return s;
	}


	@Dynamic(Field.Property.OFFSET)
	protected int fieldOffset(String field) {
		if (fieldMap.get(map(field)) == null) {
			return -1;
		}
		
		return fieldMap.get(map(field)).getOffset(this);
	}

	protected Object fieldValue(Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getValue(this);
	}

	@Dynamic(Field.Property.VALUE)
	protected Object fieldValue(String field) {
		return fieldMap.get(map(field)).getValue(this);
	}

	protected <V> V fieldValue(Class<V> c, Enum<? extends Enum<?>> field) {
		return fieldMap.get(map(field)).getValue(c, this);
	}

	protected <V> V fieldValue(Class<V> c, String field) {
		return fieldMap.get(map(field)).getValue(c, this);
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
	public void addField(Enum<? extends Enum<?>> field, String value, int offset) {
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
		this.fieldMap.put(map(field), new Entry(value, offset, length, field
		    .name(), null));
	}

	/**
	 * @param name
	 * @param value
	 * @param offset
	 * @param length
	 */
	public void addField(String name, String value, int offset, int length) {
		this.fieldMap.put(name, new Entry(value, offset, length, name, null));
	}

	/**
	 * 
	 */
	public void clearFields() {
		this.fieldMap.clear();
	}
}
