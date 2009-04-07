/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.packet.annotate;

/**
 * Annotation marks a method as an analyzer method which gets called during
 * analysis phase, if requested by user.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public @interface Analyzer {

	/**
	 * Default analyzer priority level if one is not specified explicitely
	 */
	public final static int DEFAULT_PRIORITY = 100;

	/**
	 * Analyzer priority when analyzers assemble themselves for packet processing
	 * 
	 * @return priority of this analyzer
	 */
	int priority() default DEFAULT_PRIORITY;
}
