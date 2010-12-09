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

// TODO: Auto-generated Javadoc
/**
 * The Interface HeaderLength.
 */
@Target(ElementType.METHOD)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface HeaderLength {

	/**
	 * The Enum Type.
	 */
	public enum Type {

		/** The PREFIX. */
		PREFIX,

		/** The HEADER. */
		HEADER,

		/** The GAP. */
		GAP,

		/** The PAYLOAD. */
		PAYLOAD,

		/** The POSTFIX. */
		POSTFIX
	}

	/**
	 * Value.
	 * 
	 * @return the type
	 */
//	int value() default -1;

	/**
	 * Sets the type of length getter method this is. The default is that the
	 * length getter is for a header.
	 * 
	 * @return type of length getter method
	 */
	Type value() default Type.HEADER;
}
