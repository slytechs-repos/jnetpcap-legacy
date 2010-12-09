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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.jnetpcap.packet.format.JFormatter.Priority;

// TODO: Auto-generated Javadoc
/**
 * The Interface Field.
 */
@Target(value= {ElementType.METHOD, ElementType.TYPE, ElementType.FIELD})
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Field {

	/**
	 * The Enum Property.
	 */
	public enum Property {
		
		/** The CHECK. */
		CHECK,
		
		/** The OFFSET. */
		OFFSET,
		
		/** The LENGTH. */
		LENGTH,
		
		/** The VALUE. */
		VALUE,
		
		/** The DESCRIPTION. */
		DESCRIPTION,
		
		/** The DISPLAY. */
		DISPLAY,
		
		/** The MASK. */
		MASK,
		
		/** The UNITS. */
		UNITS,
	}

	/** The Constant EMPTY. */
	public final static String EMPTY = "";

	/** The Constant DEFAULT_FORMAT. */
	public final static String DEFAULT_FORMAT = "%s";

	/**
	 * Offset.
	 * 
	 * @return the int
	 */
	int offset() default -1;

	/**
	 * Length.
	 * 
	 * @return the int
	 */
	int length() default -1;

	/**
	 * Name.
	 * 
	 * @return the string
	 */
	String name() default EMPTY;

	/**
	 * Display.
	 * 
	 * @return the string
	 */
	String display() default EMPTY;

	/**
	 * Nicname.
	 * 
	 * @return the string
	 */
	String nicname() default EMPTY;

	/**
	 * Format.
	 * 
	 * @return the string
	 */
	String format() default DEFAULT_FORMAT;

	/**
	 * Units.
	 * 
	 * @return the string
	 */
	String units() default EMPTY;

	/**
	 * Description.
	 * 
	 * @return the string
	 */
	String description() default EMPTY;

	/**
	 * Parent.
	 * 
	 * @return the string
	 */
	String parent() default EMPTY;

	/**
	 * Mask.
	 * 
	 * @return the long
	 */
	public long mask() default 0xFFFFFFFFFFFFFFFFL;

	/**
	 * Priority.
	 * 
	 * @return the priority
	 */
	Priority priority() default Priority.MEDIUM;

}
