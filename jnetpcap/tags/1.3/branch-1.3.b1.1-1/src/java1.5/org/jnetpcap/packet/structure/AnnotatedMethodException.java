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


/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AnnotatedMethodException
    extends HeaderDefinitionError {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1165114276807013103L;

	private final Class<?> c;

	/**
	 * 
	 */
	public AnnotatedMethodException(Class<?> c) {
		super(c);
		this.c = c;
	}

	/**
	 * @param message
	 */
	public AnnotatedMethodException(String message) {
		super(message);
		this.c = null;
	}

	/**
	 * @param message
	 */
	public AnnotatedMethodException(Class<?> c, String message) {
		super(c, message);
		this.c = c;
	}

	/**
	 * @param cause
	 */
	public AnnotatedMethodException(Throwable cause) {
		super(cause);
		this.c = null;

	}

	/**
	 * @param cause
	 */
	public AnnotatedMethodException(Class<?> c, Throwable cause) {
		super(c, cause);
		this.c = c;

	}

	/**
	 * @param message
	 * @param cause
	 */
	public AnnotatedMethodException(String message, Throwable cause) {
		super(message, cause);

		this.c = null;
	}

	/**
	 * @param message
	 * @param cause
	 */
	public AnnotatedMethodException(Class<?> c, String message, Throwable cause) {
		super(c, message, cause);
		this.c = c;
	}

	public Class<?> getHeader() {
		return c;
	}
}
