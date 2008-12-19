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
package org.jnetpcap.packet.format;

import org.jnetpcap.packet.JHeader;
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
	protected JField[] componentFields;

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
	 * @param componentFields
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
	 * @param componentFields
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
	 * @param componentFields
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
	 * @param componentFields
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
	 * @param componentFields
	 *          sub-fields
	 */
	public JField(Style style, Priority priority, String name, String nicname,
	    String units, JFieldRuntime<? extends JHeader, ?> runtime,
	    JField... componentFields) {
		this.name = name;
		this.nicname = nicname;
		this.priority = priority;
		this.units = units;
		this.style = style;
		this.runtime = runtime;
		this.componentFields = componentFields;
		this.display = name;

		for (JField f : componentFields) {
			f.setParent(this);
		}
	}
	
	public JField(Style style, Priority priority, String name, String display, String nicname,
	    String units, JFieldRuntime<? extends JHeader, ?> runtime,
	    JField... componentFields) {
		this.name = name;
		this.nicname = nicname;
		this.priority = priority;
		this.units = units;
		this.style = style;
		this.runtime = runtime;
		this.componentFields = componentFields;
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
	 * @param componentFields
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
	public JField[] getCompoundFields() {
		return componentFields;
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
	public boolean isCompound() {
		return componentFields.length != 0;
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

}