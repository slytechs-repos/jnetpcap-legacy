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
	private JField[] componentFields;

	private final String name;

	private final String nicname;

	private JField parent;

	private final Priority priority;

	private final JFieldRuntime<? extends JHeader, ?> runtime;

	private final Style style;

	private final String units;

	/**
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param runtime
	 * @param units
	 */
	public JField(Priority priority, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this(Style.INT_DEC, priority, name, nicname, null, runtime, componentFields);
	}

	/**
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param units
	 * @param runtime
	 */
	public JField(Priority priority, String name, String nicname, String units,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this(Style.INT_DEC, priority, name, nicname, units, runtime,
		    componentFields);
	}

	/**
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param runtime
	 * @param units
	 */
	public JField(String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this(Style.INT_DEC, Priority.MEDIUM, name, nicname, null, runtime,
		    componentFields);
	}

	public JField(Style style, Priority priority, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this(style, priority, name, nicname, null, runtime, componentFields);

	}

	/**
	 * @param style
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param units
	 * @param runtime
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

		for (JField f : componentFields) {
			f.setParent(this);
		}
	}

	public JField(Style style, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		this(style, Priority.MEDIUM, name, nicname, null, runtime, componentFields);

	}

	public JField[] getCompoundFields() {
		return componentFields;
	}

	/**
	 * @return the name
	 */
	public final String getName() {
		return this.name;
	}

	/**
	 * @return the nicname
	 */
	public String getNicname() {
		return nicname;
	}

	/**
	 * @return the parent
	 */
	public final JField getParent() {
		return this.parent;
	}

	/**
	 * @return the priority
	 */
	public Priority getPriority() {
		return priority;
	}

	/**
	 * @return the runtime
	 */
	public JFieldRuntime<? extends JHeader, ?> getRuntime() {
		return runtime;
	}

	/**
	 * @return the style
	 */
	public Style getStyle() {
		return style;
	}

	/**
	 * @return the units
	 */
	public String getUnits() {
		return units;
	}

	public boolean isCompound() {
		return componentFields.length != 0;
	}

	/**
	 * @param parent
	 *          the parent to set
	 */
	public final void setParent(JField parent) {
		this.parent = parent;
	}
}