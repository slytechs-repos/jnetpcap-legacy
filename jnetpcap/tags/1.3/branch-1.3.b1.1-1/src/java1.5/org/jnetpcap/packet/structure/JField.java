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
package org.jnetpcap.packet.structure;

import java.util.Arrays;
import java.util.Comparator;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * A field within a header. Field objects are used to describe the structure of
 * a header to a formatter. The formatter iterates through all the fields it
 * receives from a header and using formatting information stored in these
 * fields, creates formatted output.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JField {

	private static class JFieldComp implements Comparator<JField> {

		private JHeader header;

		private boolean ascending = true;

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		@SuppressWarnings("unchecked")
		public int compare(JField o1, JField o2) {
			if (ascending) {
				return o1.getOffset(header) - o2.getOffset(header);
			} else {
				return o2.getOffset(header) - o1.getOffset(header);
			}
		}

		public void setHeader(JHeader header) {
			this.header = header;
		}

		public void setAscending(boolean ascending) {
			this.ascending = ascending;
		}

	}

	public static void sortFieldByOffset(
	    JField[] fields,
	    JHeader header,
	    boolean ascending) {

		SORT_BY_OFFSET.setAscending(ascending);
		SORT_BY_OFFSET.setHeader(header);
		Arrays.sort(fields, SORT_BY_OFFSET);
	}

	private final static JFieldComp SORT_BY_OFFSET = new JFieldComp();

	protected JField[] subFields;

	/**
	 * Name of the field which is also its ID
	 */
	private final String name;

	private final String nicname;

	private JField parent;

	private final Priority priority;

	protected Style style;

	private final AnnotatedFieldMethod value;

	private final AnnotatedFieldMethod offset;

	private final AnnotatedFieldMethod length;

	private final AnnotatedFieldMethod display;

	private final AnnotatedFieldMethod description;

	private final AnnotatedFieldMethod mask;

	private final AnnotatedFieldMethod check;

	private AnnotatedFieldMethod units;

	public String toString() {
		StringBuilder b = new StringBuilder();

		b.append("name=").append(name);
		b.append(", nicname=").append(nicname);
		b.append(", parent=").append(parent);
		b.append(", priority=").append(priority);
		b.append(", style=").append(style);

		return b.toString();
	}

	public JField(AnnotatedField afield, JField[] children) {
		this.subFields = children;
		this.priority = afield.getPriority();
		this.name = afield.getName();
		this.nicname = afield.getNicname();
		afield.getDisplay();
		afield.getUnits();
		this.style = afield.getStyle();
		
		value = afield.getRuntime().getFunctionMap().get(Field.Property.VALUE);
		offset = afield.getRuntime().getFunctionMap().get(Field.Property.OFFSET);
		length = afield.getRuntime().getFunctionMap().get(Field.Property.LENGTH);
		display = afield.getRuntime().getFunctionMap().get(Field.Property.DISPLAY);
		description = afield.getRuntime().getFunctionMap().get(Field.Property.DESCRIPTION);
		mask = afield.getRuntime().getFunctionMap().get(Field.Property.MASK);
		check = afield.getRuntime().getFunctionMap().get(Field.Property.CHECK);
		units = afield.getRuntime().getFunctionMap().get(Field.Property.UNITS);

		for (JField f : subFields) {
			f.setParent(this);
		}
	}

	/**
	 * Gets the sub-fields
	 * 
	 * @return array of subfields
	 */
	public JField[] getSubFields() {
		return subFields;
	}

	/**
	 * Gets the full name of this field
	 * 
	 * @return the name
	 */
	public final String getName() {
		return this.name;
	}

	/**
	 * Gets the nicname of this field
	 * 
	 * @return the nicname
	 */
	public String getNicname() {
		return nicname;
	}

	/**
	 * If this field is a sub-field, this method returns a reference to the parent
	 * field
	 * 
	 * @return the parent
	 */
	public final JField getParent() {
		return this.parent;
	}

	/**
	 * Gets the current field's priority. Formatters determine if fields should be
	 * included in the output based on priorities
	 * 
	 * @return the priority
	 */
	public Priority getPriority() {
		return priority;
	}

	/**
	 * Formatting style for this field
	 * 
	 * @return the style
	 */
	public Style getStyle() {
		return style;
	}

	/**
	 * Does this field have subfields
	 * 
	 * @return true means has sub-fields, otherwise false
	 */
	public boolean hasSubFields() {
		return subFields.length != 0;
	}

	/**
	 * Sets the parent of this sub-field and only when this field is a sub-field
	 * 
	 * @param parent
	 *          the parent to set
	 */
	public final void setParent(JField parent) {
		this.parent = parent;
	}

	/**
	 * @param style
	 */
	public void setStyle(Style style) {
		this.style = style;
	}

	public String getUnits(JHeader header) {
		return units.stringMethod(header, name);
	}
	
	public boolean hasField(JHeader header) {
		return check.booleanMethod(header, name);
	}


	public String getDisplay(JHeader header) {
		return display.stringMethod(header, name);
	}

	public int getLength(JHeader header) {
		return length.intMethod(header, name);
	}
	
	public long getMask(JHeader header) {
		return mask.longMethod(header, name);
	}


	public int getOffset(JHeader header) {
		return offset.intMethod(header, name);
	}

	public String getValueDescription(JHeader header) {
		return description.stringMethod(header, name);
	}
	
	@SuppressWarnings("unchecked")
  public <T> T getValue(Class<T> c, JHeader header) {
		return (T) value.objectMethod(header, name);
	}

	public Object getValue(JHeader header) {
		return value.objectMethod(header, name);
	}

	/**
   * @param header
   * @return
   */
  public long longValue(JHeader header) {
  	Object o = getValue(header);
  	if (o instanceof Number) {
  		return ((Number) o).longValue();
  	} else if (o instanceof Boolean) {
  		return ((Boolean)o).booleanValue()?1L:0L;
  	} else if (o instanceof String) {
  		return Long.parseLong(o.toString());
  	} else {
  		throw new IllegalStateException("unknown format encountered");
  	}
  }

}