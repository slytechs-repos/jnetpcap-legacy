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
 * The IP_INTERFACE_INFO structure is specific to network adapters with IPv4
 * enabled. The IP_INTERFACE_INFO structure contains the number of network
 * adapters with IPv4 enabled on the local system and an array of
 * IP_ADAPTER_INDEX_MAP structures with information on each network adapter with
 * IPv4 enabled. The IP_INTERFACE_INFO structure contains at least one
 * IP_ADAPTER_INDEX_MAP structure even if the NumAdapters member of the
 * IP_INTERFACE_INFO structure indicates that no network adapters with IPv4 are
 * enabled. When the NumAdapters member of the IP_INTERFACE_INFO structure is
 * zero, the value of the members of the single IP_ADAPTER_INDEX_MAP structure
 * returned in the IP_INTERFACE_INFO structure is undefined. The
 * IP_INTERFACE_INFO structure can't be used to return information about the
 * loopback interface. On Windows Vista and later, the Name member of the
 * IP_ADAPTER_INDEX_MAP structure in the IP_INTERFACE_INFO structure may be a
 * Unicode string of the GUID for the network interface (the string begins with
 * the '{' character). This structure is defined in the Ipexport.h header file
 * which is automatically included in the Iphlpapi.h header file. The Ipexport.h
 * header file should never be used directly. Examples
 * 
 * <pre>
 * typedef struct _IP_INTERFACE_INFO {  
 * 	LONG NumAdapters;  
 * 	IP_ADAPTER_INDEX_MAP Adapter[1];
 * } IP_INTERFACE_INFO,  *PIP_INTERFACE_INFO;
 * </pre>
 * 
 * @see MSIpHelper#getInterfaceInfo(MSIpInterfaceInfo, org.jnetpcap.JNumber)
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class MSIpInterfaceInfo
    extends JStruct {
	
	/**
	 * Native structure name
	 */
	public static final String STRUCT_NAME = "IP_INTERFACE_INFO";

	static {
		MSIpAdapterIndexMap.isSupported();
	}

	/**
	 * Allocates <code>struct IpInterfaceInfo</code> of the specified size in
	 * bytes.
	 * 
	 * @param size
	 *          number of bytes of memory to allocate and peer to this object
	 */
	public MSIpInterfaceInfo(int size) {
		super(STRUCT_NAME, size);
	}

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
	 * The number of adapters listed in the array pointed to by the Adapter
	 * member.
	 * 
	 * @return number of adapters
	 */
	public native long numAdapters();

	/**
	 * An array of IP_ADAPTER_INDEX_MAP structures. Each structure maps an adapter
	 * index to that adapter's name. The adapter index may change when an adapter
	 * is disabled and then enabled, or under other circumstances, and should not
	 * be considered persistent.
	 * 
	 * @param index
	 *          index of the adapter
	 * @return index map structure
	 */
	public native MSIpAdapterIndexMap adapter(int index);

}
