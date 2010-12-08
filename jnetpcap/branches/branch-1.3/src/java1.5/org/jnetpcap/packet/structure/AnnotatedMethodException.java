/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
