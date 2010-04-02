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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.jnetpcap.packet.JHeader;

/**
 * Specifies global protocol properties
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unchecked")
@Target(ElementType.TYPE)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Protocol {

	public enum Suite {

		/**
		 * OSI application layer set of protocols.
		 */
		APPLICATION,
		/**
		 * Tcp/Ip family of protocols.
		 */
		TCP_IP,

		/**
		 * Security related family of protocols.
		 */
		SECURITY,

		/**
		 * Tunneling family of protocols.
		 */
		VPN,

		/**
		 * Mobile communication device family of protocols.
		 */
		MOBILE,

		/**
		 * OSI network layer family of protocols.
		 */
		NETWORK,

		/**
		 * Wireless family of protocols.
		 */
		WIRELESS,

		/**
		 * Voice over IP family of protocols.
		 */
		VOIP,

		/**
		 * Local Area Network family of protocols.
		 */
		LAN,

		/**
		 * Metropolitan Area Network family of protocols.
		 */
		MAN,

		/**
		 * Wide Area Network family of protocols.
		 */
		WAN,
		/**
		 * Storage Area Network family of protocols.
		 */
		SAN,

		/**
		 * ISO family of protocols.
		 */

		ISO,

		/**
		 * SS7 family of protocols.
		 */
		SS7,

		/**
		 * Cisco Systems family of protocols.
		 */
		CISCO,

		/**
		 * IBM family of protocols.
		 */
		IBM,

		/**
		 * Microsoft Corp family of protocols.
		 */
		MICROSOFT,

		/**
		 * Novell family of protocols.
		 */
		NOVELL,

		/**
		 * Apple Corp family of protocols.
		 */
		APPLE,

		/**
		 * Hewlet Packard Corp family of protocols.
		 */
		HP,

		/**
		 * Sun Microsystems Corp family of protocols.
		 */
		SUN,

		/**
		 * Catch all suite for other types of protocols.
		 */
		OTHER,
	}

	/**
	 * Protocol suite this prorotocol belongs to
	 * 
	 * @return protocol family for this protocol
	 */
	Suite suite() default Suite.OTHER;

	Class<? extends JHeader>[] headers() default JHeader.class;

	String[] description() default "";

	String[] license() default "";

	String company() default "";

	String[] rfcs() default "";
}
