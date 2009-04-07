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
package org.jnetpcap.packet.annotate;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.jnetpcap.packet.JHeader;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Target(ElementType.METHOD)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Bind {

	int[] intValue() default Integer.MAX_VALUE;

	String[] stringValue() default "";

	/**
	 * The protocol that wants to bind to another protocol. In the diagram below B
	 * is binding to A. That is "to" == A.class. This is called the <b>target</b>
	 * protocol.
	 * <p>
	 * In this example, <b>to</b> paramter is assigned to header <b>A class</b>
	 * 
	 * <pre>
	 * +----------+----------------+----------+ 
	 * | Ethernet | =&gt; header A &lt;= | header B |
	 * +----------+----------------+----------+
	 * </pre>
	 * 
	 * </p>
	 * Another words, <b>B header</b> is binding <u>to</u> <b>A header</b>
	 * 
	 * @return a header class that is the target of the binding
	 */
	Class<? extends JHeader> to();

	/**
	 * The protocol that is being bound to. In the diagram below B is binding to
	 * A. That is "from" == B.class. This is called the <b>source</b> protocol.
	 * <p>
	 * In this example, <b>from</b> paramter is assigned to header <b>B class</b>
	 * 
	 * <pre>
	 * +----------+----------+----------------+ 
	 * | Ethernet | header A | =&gt; header B &lt;= |
	 * +----------+----------+----------------+
	 * </pre>
	 * 
	 * Another words, <b>A header</b> is bind is bound <u>from</u> <b>B header</b>
	 * </p>
	 * 
	 * @return header class that is the source of the binding
	 */
	Class<? extends JHeader> from() default JHeader.class;
}
