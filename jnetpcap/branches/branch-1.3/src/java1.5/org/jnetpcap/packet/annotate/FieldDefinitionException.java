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
package org.jnetpcap.packet.annotate;

import org.jnetpcap.packet.structure.AnnotatedField;
import org.jnetpcap.packet.structure.HeaderDefinitionError;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class FieldDefinitionException
    extends HeaderDefinitionError {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2116907712440514743L;

	private final AnnotatedField field;

	/**
	 * @param field
	 */
	public FieldDefinitionException(AnnotatedField field) {
		super(field.getDeclaringClass());
		this.field = field;
	}

	/**
	 * @param message
	 */
	public FieldDefinitionException(String message) {
		super(message);
		this.field = null;
	}

	/**
	 * @param field
	 * @param message
	 */
	public FieldDefinitionException(AnnotatedField field, String message) {
		super(field.getDeclaringClass(), message);
		this.field = field;
	}

	/**
	 * @param cause
	 */
	public FieldDefinitionException(Throwable cause) {
		super(cause);
		this.field = null;
	}

	/**
	 * @param field
	 * @param cause
	 */
	public FieldDefinitionException(AnnotatedField field, Throwable cause) {
		super(field.getDeclaringClass(), cause);
		this.field = field;
	}

	/**
	 * @param message
	 * @param cause
	 */
	public FieldDefinitionException(String message, Throwable cause) {
		super(message, cause);
		this.field = null;
	}

	/**
	 * @param field
	 * @param message
	 * @param cause
	 */
	public FieldDefinitionException(AnnotatedField field, String message,
	    Throwable cause) {
		super(field.getDeclaringClass(), message, cause);
		this.field = field;
	}

	public final AnnotatedField getField() {
		return this.field;
	}

	protected String getPath() {
		return super.getPath() + field.getName();
	}
	
}
