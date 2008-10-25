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

import org.jnetpcap.nio.JStruct;

/**
 * The IP_ADAPTER_INDEX_MAP structure is specific to network adapters with IPv4
 * enabled. An adapter index may change when the adapter is disabled and then
 * enabled, or under other circumstances, and should not be considered
 * persistent. On Windows Vista and later, the Name member of the
 * IP_ADAPTER_INDEX_MAP structure may be a Unicode string of the GUID for the
 * network interface (the string begins with the '{' character). 
 * 
 * <pre>
 * typedef struct _IP_ADAPTER_INDEX_MAP {
 *   ULONG Index;  
 *   WCHAR Name[MAX_ADAPTER_NAME];
 * } IP_ADAPTER_INDEX_MAP,  *PIP_ADAPTER_INDEX_MAP;
 * </pre>
 * 
 * @see MSIpInterfaceInfo#adapter(int)
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class MSIpAdapterIndexMap
    extends JStruct  {

	/**
	 * Native structure name
	 */
	public static final String STRUCT_NAME = "IP_ADAPTER_INDEX_MAP";

	/**
	 * Setup as a pointer.
	 */
	public MSIpAdapterIndexMap() {
		super(STRUCT_NAME);
	}
	
	static {
		initIDs();
	}
	
	private native static void initIDs();
	
	/**
	 * Checks if this extension is supported on this platform. This method does
	 * not throw any exceptions and is safe to use on any platform.
	 * 
	 * @return true means it is supported, otherwise false
	 */
	public static boolean isSupported() {
		return MSIpHelper.isSupported();
	}

	/**
	 * The interface index associated with the network adapter.
	 * 
	 * @return index
	 */
	public native int index();

	/**
	 * string that contains the name of the adapter.
	 * 
	 * @return name
	 */
	public native String name();

}
