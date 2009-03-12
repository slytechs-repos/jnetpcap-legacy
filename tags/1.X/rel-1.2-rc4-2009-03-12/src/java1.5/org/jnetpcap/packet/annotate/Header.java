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

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.protocol.JProtocol.Suite;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Target(ElementType.TYPE)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Header {
	public enum Layer {
		NULL,
		PHYSICAL,
		DATALINK,
		NETWORK,
		TRANSPORT,
		SESSION,
		PRESENTATION,
		APPLICATION,
	}
	
	public enum Characteristic {
		NULL,
		POINT_TO_POINT,
		POINT_TO_MULTIPOINT,
		CSMA_CD,

	}
	
	Characteristic[] characteristics() default {};

	String description() default "";
	
	PcapDLT[] dlt() default {};
	
	String format() default "";
	
	int id() default -1;
	
	int length() default -1;
	
	String name() default "";
	
	String nicname() default "";
	
	ProtocolSuite suite() default ProtocolSuite.OTHER;
	
	Layer osi() default Layer.NULL;
	
	Class<? extends JHeader> parent() default JHeader.class;
	
	String[] spec() default {};

	String url() default "";
}
