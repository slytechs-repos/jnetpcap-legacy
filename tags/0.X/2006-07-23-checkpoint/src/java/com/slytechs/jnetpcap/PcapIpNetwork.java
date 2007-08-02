/**
 * $Id$
 * Copyright (C) 2006 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com.slytechs.jnetpcap;

import java.net.InetAddress;

/**
 * PCAP specific IP address and associated netmask that
 * can be retrieved from a PcapNetworkInterface.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapIpNetwork {

	/**
	 * Netmask of this network address.
	 * 
	 * @return netmask for this address.
	 */
	public byte[] getNetmask() {
	
		return null;
	}
	
	/**
	 * Address portion of this network address. Netmask is
	 * not applied and address is not truncated to the number of
	 * bits in the netmask.
	 * 
	 * @return Address portion of this network address.
	 */
	public byte[] getAddress() {
		return null;
	}
	
	/**
	 * Converted address to an InetAddress object part so that further
	 * name service queries can be made such as hostname lookup.
	 * 
	 * @return Full InetAddress name service lookup facility.
	 */
	public InetAddress getInetAddress() {
		return null;
	}
}
