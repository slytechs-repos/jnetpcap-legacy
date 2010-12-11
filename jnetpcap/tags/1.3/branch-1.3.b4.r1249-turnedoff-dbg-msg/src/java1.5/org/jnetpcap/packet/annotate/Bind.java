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

import org.jnetpcap.packet.JHeader;

// TODO: Auto-generated Javadoc
/**
 * The Interface Bind.
 */
@Target(ElementType.METHOD)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Bind {

	/**
	 * The Enum Type.
	 */
	public enum Type {
		
		/** The PRIMARY. */
		PRIMARY,

		/** The HEURISTIC. */
		HEURISTIC
	}

	/**
	 * Int value.
	 * 
	 * @return the int[]
	 */
	int[] intValue() default Integer.MAX_VALUE;

	/**
	 * String value.
	 * 
	 * @return the string[]
	 */
	String[] stringValue() default "";

	/**
	 * To.
	 * 
	 * @return the class<? extends j header>
	 */
	Class<? extends JHeader> to();

	/**
	 * From.
	 * 
	 * @return the class<? extends j header>
	 */
	Class<? extends JHeader> from() default JHeader.class;

	/**
	 * Dependencies.
	 * 
	 * @return the class<? extends j header>[]
	 */
	Class<? extends JHeader>[] dependencies() default {};

	/**
	 * Type.
	 * 
	 * @return the type
	 */
	Type type() default Type.PRIMARY;
}
