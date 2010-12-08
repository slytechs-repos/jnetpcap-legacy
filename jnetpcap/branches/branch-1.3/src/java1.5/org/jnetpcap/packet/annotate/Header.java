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

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;

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
	
	int prefix() default -1;
	
	int gap() default  -1;
	
	int payload() default -1;
	
	int postfix() default -1;
	
	String name() default "";
	
	String nicname() default "";
	
	ProtocolSuite suite() default ProtocolSuite.OTHER;
	
	Layer osi() default Layer.NULL;
	
	Class<? extends JHeader> parent() default JHeader.class;
	
	String[] spec() default {};

	String url() default "";
}
