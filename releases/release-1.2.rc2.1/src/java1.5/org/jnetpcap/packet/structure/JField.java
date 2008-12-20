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
import org.jnetpcap.packet.annotate.FieldRuntime.FieldFunction;
import org.jnetpcap.packet.format.DefaultFieldRuntime;
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

		private JFieldRuntime<JHeader, Object> r1;

		private JFieldRuntime<JHeader, Object> r2;

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		@SuppressWarnings("unchecked")
		public int compare(JField o1, JField o2) {
			r1 = (JFieldRuntime<JHeader, Object>) o1.getRuntime();
			r2 = (JFieldRuntime<JHeader, Object>) o2.getRuntime();

			if (ascending) {
				return r1.getOffset(header) - r2.getOffset(header);
			} else {
				return r2.getOffset(header) - r1.getOffset(header);
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

	/**
	 * Display name, used for displaying to the user
	 */
	private final String display;

	private final String nicname;

	private JField parent;

	private final Priority priority;

	private JFieldRuntime<? extends JHeader, ?> runtime;

	protected Style style;

	private final String units;

	private AnnotatedField afield;

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
		this.afield = afield;
		this.subFields = children;
		this.priority = afield.getPriority();
		this.name = afield.getName();
		this.nicname = afield.getNicname();
		this.display = afield.getDisplay();
		this.units = afield.getUnits();
		this.style = afield.getStyle();
		this.runtime = new DefaultFieldRuntime(afield.getRuntime());
		
		for (JField f : subFields) {
			f.setParent(this);
		}
	}

	/**
	 * Creates a field of a header
	 * 
	 * @param priority
	 *          fields priority when choosing fields by priorities
	 * @param name
	 *          full name of the field
	 * @param nicname
	 *          nicname of the field
	 * @param runtime
	 *          runtime environment for this field
	 * @param subFields
	 *          sub-fields
	 */
	public JField(Priority priority, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this(Style.INT_DEC, priority, name, nicname, null, runtime, componentFields);
	}

	/**
	 * Creates a field of a header
	 * 
	 * @param priority
	 *          fields priority when choosing fields by priorities
	 * @param name
	 *          full name of the field
	 * @param nicname
	 *          nicname of the field
	 * @param units
	 *          units of the value
	 * @param runtime
	 *          runtime environment for this field
	 * @param subFields
	 *          sub-fields
	 */
	public JField(Priority priority, String name, String nicname, String units,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this(Style.INT_DEC, priority, name, nicname, units, runtime,
		    componentFields);
	}

	/**
	 * Creates a field of a header
	 * 
	 * @param name
	 *          full name of the field
	 * @param nicname
	 *          nicname of the field
	 * @param runtime
	 *          runtime environment for this field
	 * @param subFields
	 *          sub-fields
	 */
	public JField(String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this(Style.INT_DEC, Priority.MEDIUM, name, nicname, null, runtime,
		    componentFields);
	}

	/**
	 * Creates a field of a header
	 * 
	 * @param style
	 *          formatting style options
	 * @param priority
	 *          fields priority when choosing fields by priorities
	 * @param name
	 *          full name of the field
	 * @param nicname
	 *          nicname of the field
	 * @param runtime
	 *          runtime environment for this field
	 * @param subFields
	 *          sub-fields
	 */
	public JField(Style style, Priority priority, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this(style, priority, name, nicname, null, runtime, componentFields);

	}

	/**
	 * Creates a field of a header
	 * 
	 * @param style
	 *          formatting style options
	 * @param priority
	 *          fields priority when choosing fields by priorities
	 * @param name
	 *          full name of the field
	 * @param nicname
	 *          nicname of the field
	 * @param units
	 *          units description for the value
	 * @param runtime
	 *          runtime environment for this field
	 * @param subFields
	 *          sub-fields
	 */
	public JField(Style style, Priority priority, String name, String nicname,
	    String units, JFieldRuntime<? extends JHeader, ?> runtime,
	    JField... subFields) {
		this.name = name;
		this.nicname = nicname;
		this.priority = priority;
		this.units = units;
		this.style = style;
		this.runtime = runtime;
		this.subFields = subFields;
		this.display = name;

		for (JField f : subFields) {
			f.setParent(this);
		}
	}

	public JField(Style style, Priority priority, String name, String display,
	    String nicname, String units,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this.name = name;
		this.nicname = nicname;
		this.priority = priority;
		this.units = units;
		this.style = style;
		this.runtime = runtime;
		this.subFields = componentFields;
		this.display = display;

		for (JField f : componentFields) {
			f.setParent(this);
		}
	}

	/**
	 * Creates a field of a header
	 * 
	 * @param style
	 *          formatting style options
	 * @param name
	 *          full name of the field
	 * @param nicname
	 *          nicname of the field
	 * @param runtime
	 *          runtime environment for this field
	 * @param subFields
	 *          sub-fields
	 */
	public JField(Style style, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this(style, Priority.MEDIUM, name, nicname, null, runtime, componentFields);

	}

	public void setRuntime(JFieldRuntime<? extends JHeader, ?> runtime) {
		this.runtime = runtime;
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
	 * Runtime environment for this field
	 * 
	 * @return the runtime
	 */
	public JFieldRuntime<? extends JHeader, ?> getRuntime() {
		return runtime;
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
	 * Units for the value
	 * 
	 * @return the units
	 */
	public String getUnits() {
		return units;
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

	public final String getDisplay() {
		return this.display;
	}

	public int getOffset(JHeader header) {

		AnnotatedFieldMethod method =
		    afield.getRuntime().getFunctionMap().get(FieldFunction.OFFSET);
		
		return method.intMethod(header);
	}
	
	public Object getValue(JHeader header) {
		AnnotatedFieldMethod method =
		    afield.getRuntime().getFunctionMap().get(FieldFunction.VALUE);
		
		return method.objectMethod(header);
	}

}