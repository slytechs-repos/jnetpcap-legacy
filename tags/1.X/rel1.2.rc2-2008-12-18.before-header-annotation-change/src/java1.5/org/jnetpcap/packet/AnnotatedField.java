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

import java.lang.reflect.Method;

import org.jnetpcap.packet.format.JField;
import org.jnetpcap.packet.format.JFieldRuntime;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedField
    extends JField {

	private Method method;

	/**
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param runtime
	 * @param componentFields
	 */
	public AnnotatedField(Priority priority, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		super(priority, name, nicname, runtime, componentFields);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param units
	 * @param runtime
	 * @param componentFields
	 */
	public AnnotatedField(Priority priority, String name, String nicname,
	    String units, JFieldRuntime<? extends JHeader, ?> runtime,
	    JField... componentFields) {
		super(priority, name, nicname, units, runtime, componentFields);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param name
	 * @param nicname
	 * @param runtime
	 * @param componentFields
	 */
	public AnnotatedField(String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		super(name, nicname, runtime, componentFields);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param style
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param runtime
	 * @param componentFields
	 */
	public AnnotatedField(Style style, Priority priority, String name,
	    String nicname, JFieldRuntime<? extends JHeader, ?> runtime,
	    JField... componentFields) {
		super(style, priority, name, nicname, runtime, componentFields);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param style
	 * @param priority
	 * @param name
	 * @param nicname
	 * @param units
	 * @param runtime
	 * @param componentFields
	 */
	public AnnotatedField(Style style, Priority priority, String name,
	    String display, String nicname, String units, Method method) {
		super(style, priority, name, display, nicname, units, null);
		this.method = method;
	}

	/**
	 * @param style
	 * @param name
	 * @param nicname
	 * @param runtime
	 * @param componentFields
	 */
	public AnnotatedField(Style style, String name, String nicname,
	    JFieldRuntime<? extends JHeader, ?> runtime, JField... componentFields) {
		super(style, name, nicname, runtime, componentFields);
	}

	public final Method getMethod() {
		return this.method;
	}

	public final void setMethod(Method method) {
		this.method = method;
	}

	/**
	 * @param fields
	 */
	public void addSubFields(AnnotatedField[] fields) {
		super.componentFields = fields;
	}

}
