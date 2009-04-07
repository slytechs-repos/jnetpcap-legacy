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

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JNumber;

/**
 * The Internet Protocol Helper (IP Helper) API enables the retrieval and
 * modification of network configuration settings for the local computer. Where
 * Applicable The IP Helper API is applicable in any computing environment where
 * programmatically manipulating TCP/IP configuration is useful. Typical
 * applications include IP routing protocols and Simple Network Management
 * Protocol (SNMP) agents.
 * 
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class MSIpHelper {

	/**
	 * The operation completed successfully.
	 */
	public final static int ERROR_SUCCESS = 0;

	/**
	 * The operation completed successfully.
	 */
	public final static int NO_ERROR = ERROR_SUCCESS;

	/**
	 * The data area passed to a system call is too small.
	 */
	public final static int ERROR_INSUFFICIENT_BUFFER = 122;

	/**
	 * The parameter is incorrect.
	 */
	public final static int ERROR_INVALID_PARAMETER = 87;

	/**
	 * The pipe is being closed.
	 */
	public final static int ERROR_NO_DATA = 232;

	/**
	 * The request is not supported.
	 */
	public final static int ERROR_NOT_SUPPORTED = 50;

	/**
	 * The file name is too long.
	 */
	public final static int ERROR_BUFFER_OVERFLOW = 111;

	/**
	 * The data is invalid.
	 */
	public final static int ERROR_INVALID_DATA = 13;

	/**
	 * Cannot complete this function.
	 */
	public final static int ERROR_CAN_NOT_COMPLETE = 1003;

	static {
		Pcap.isInjectSupported();
	}

	/**
	 * Prevent instantiation
	 */
	private MSIpHelper() {
		// Emtpy
	}

	/**
	 * The GetInterfaceInfo function obtains the list of the network interface
	 * adapters with IPv4 enabled on the local system. The call is typically made
	 * twice, the first time to acquire the size of the neccessary info structure
	 * and then the second time with the allocated structure.
	 * <h2>Example</h2>
	 * 
	 * <pre>
	 * JNumber size = new JNumber();
	 * MSIpHelper.getInterfaceInfo(null, size);
	 * 
	 * MSIpInterfaceInfo info = new MSIpInterfaceInfo(size.intValue());
	 * MSIpHelper.getInterfaceInfo(info, size);
	 * 
	 * System.out.println(info.numAdapters());
	 * </pre>
	 * 
	 * @param info
	 *          A pointer to a buffer that specifies an IP_INTERFACE_INFO
	 *          structure that receives the list of adapters. This buffer must be
	 *          allocated by the caller. If null, the size parameter is filled in
	 *          with the size (number of bytes) required to be allocated in order
	 *          to fit the IpInterfaceInfo structure.
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

	/**
	 * The GetIfEntry function retrieves information for an interface on a local
	 * computer. The dwIndex member in the MIB_IFROW structure pointed to by the
	 * pIfRow parameter must be initialized to a valid network interface index
	 * retrieved by a previous call to the GetIfTable, GetIfTable2, or
	 * GetIfTable2Ex function. The GetIfEntry function will fail if the dwIndex
	 * member of the MIB_IFROW pointed to by the pIfRow parameter does not match
	 * an existing interface index on the local computer.
	 * 
	 * @param row
	 *          A pointer to a MIB_IFROW structure that, on successful return,
	 *          receives information for an interface on the local computer. On
	 *          input, set the dwIndex member of MIB_IFROW to the index of the
	 *          interface for which to retrieve information. The value for the
	 *          dwIndex must be retrieved by a previous call to the GetIfTable,
	 *          GetIfTable2, or GetIfTable2Ex function.
	 * @return If the function succeeds, the return value is NO_ERROR.
	 */
	public static native int getIfEntry(MSMibIfRow row);

	/**
	 * Checks if this extension is supported on this platform. This method does
	 * not throw any exceptions and is safe to use on any platform.
	 * 
	 * @return true means it is supported, otherwise false
	 */
	public native static boolean isSupported();

}
