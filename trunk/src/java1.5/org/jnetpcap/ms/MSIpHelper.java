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
package org.jnetpcap.ms;

import org.jnetpcap.JNumber;

/**
 * The Internet Protocol Helper (IP Helper) API enables the retrieval and
 * modification of network configuration settings for the local computer. Where
 * Applicable The IP Helper API is applicable in any computing environment where
 * programmatically manipulating TCP/IP configuration is useful. Typical
 * applications include IP routing protocols and Simple Network Management
 * Protocol (SNMP) agents. Developer Audience
 * 
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class MSIpHelper {

	/**
	 * Prevent instantiation
	 */
	private MSIpHelper() {
		// Emtpy
	}

	/**
	 * The GetInterfaceInfo function obtains the list of the network interface
	 * adapters with IPv4 enabled on the local system.
	 * 
	 * @param info
	 *          A pointer to a buffer that specifies an IP_INTERFACE_INFO
	 *          structure that receives the list of adapters. This buffer must be
	 *          allocated by the caller.
	 * @param size
	 *          A pointer to a DWORD variable that specifies the size of the
	 *          buffer pointed to by pIfTable parameter to receive the
	 *          IP_INTERFACE_INFO structure. If this size is insufficient to hold
	 *          the IPv4 interface information, GetInterfaceInfo fills in this
	 *          variable with the required size, and returns an error code of
	 *          ERROR_INSUFFICIENT_BUFFER.
	 * @return if the function succeeds, the return value is NO_ERROR
	 */
	public static native int getInterfaceInfo(MSIpInterfaceInfo info, JNumber size);

}
