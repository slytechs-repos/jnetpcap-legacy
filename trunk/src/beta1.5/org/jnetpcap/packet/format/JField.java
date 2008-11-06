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
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JField {
	public final String name;

	public final String nicname;

	public final Priority priority;

	public final JFieldRuntime<? extends JHeader, ?> runtime;

	public final Style style;

	public final String units;

	/**
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param runtime
	 * @param units
	 */
	public JField(String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime) {
		this(Style.INT_DEC, Priority.MEDIUM, name, nicname, null, runtime);
	}

	/**
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param runtime
	 * @param units
	 */
	public JField(Priority priority, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime) {
		this(Style.INT_DEC, priority, name, nicname, null, runtime);
	}

	/**
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param units
	 * @param runtime
	 */
	public JField(Priority priority, String name, String nicname, String units,
	    JFieldRuntime<? extends JHeader, ?> runtime) {
		this(Style.INT_DEC, priority, name, nicname, units, runtime);
	}

	public JField(Style style, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime) {
		this(style, Priority.MEDIUM, name, nicname, null, runtime);

	}

	public JField(Style style, Priority priority, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime) {
		this(style, priority, name, nicname, null, runtime);

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
	    String units, JFieldRuntime<? extends JHeader, ?> runtime) {
		this.name = name;
		this.nicname = nicname;
		this.priority = priority;
		this.units = units;
		this.style = style;
		this.runtime = runtime;
	}

	public boolean isCompound() {
		return getCompoundFields() != null;
	}

	public JField[] getCompoundFields() {
		return null;
	}
}