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
 * The Interface Protocol.
 */
@Target(ElementType.TYPE)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Protocol {

	/**
	 * The Enum Suite.
	 */
	public enum Suite {

		/** The APPLICATION. */
		APPLICATION,
		
		/** The TC p_ ip. */
		TCP_IP,

		/** The SECURITY. */
		SECURITY,

		/** The VPN. */
		VPN,

		/** The MOBILE. */
		MOBILE,

		/** The NETWORK. */
		NETWORK,

		/** The WIRELESS. */
		WIRELESS,

		/** The VOIP. */
		VOIP,

		/** The LAN. */
		LAN,

		/** The MAN. */
		MAN,

		/** The WAN. */
		WAN,
		
		/** The SAN. */
		SAN,

		/** The ISO. */

		ISO,

		/** The S s7. */
		SS7,

		/** The CISCO. */
		CISCO,

		/** The IBM. */
		IBM,

		/** The MICROSOFT. */
		MICROSOFT,

		/** The NOVELL. */
		NOVELL,

		/** The APPLE. */
		APPLE,

		/** The HP. */
		HP,

		/** The SUN. */
		SUN,

		/** The OTHER. */
		OTHER,
	}

	/**
	 * Suite.
	 * 
	 * @return the suite
	 */
	Suite suite() default Suite.OTHER;

	/**
	 * Headers.
	 * 
	 * @return the class<? extends j header>[]
	 */
	Class<? extends JHeader>[] headers() default JHeader.class;

	/**
	 * Description.
	 * 
	 * @return the string[]
	 */
	String[] description() default "";

	/**
	 * License.
	 * 
	 * @return the string[]
	 */
	String[] license() default "";

	/**
	 * Company.
	 * 
	 * @return the string
	 */
	String company() default "";

	/**
	 * Rfcs.
	 * 
	 * @return the string[]
	 */
	String[] rfcs() default "";
}
