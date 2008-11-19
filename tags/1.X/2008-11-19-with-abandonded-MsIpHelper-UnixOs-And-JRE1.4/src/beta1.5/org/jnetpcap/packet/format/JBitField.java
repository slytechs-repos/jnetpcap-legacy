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
public class JBitField
    extends JField {

	/**
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param runtime
	 */
	public JBitField(Priority priority, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime) {
		this(Style.INT_BITS, priority, name, nicname, runtime);
	}

	/**
	 * @param name
	 * @param nicname
	 * @param runtime
	 * @param style
	 */
	public JBitField(String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime) {
		this(Style.INT_BITS, Priority.MEDIUM, name, nicname, runtime);
	}

	/**
	 * @param style
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param runtime
	 */
	private JBitField(Style style, Priority priority, String name,
	    String nicname, JFieldRuntime<? extends JHeader, ?> runtime) {
		super(style, priority, name, nicname, runtime);
	}

}
