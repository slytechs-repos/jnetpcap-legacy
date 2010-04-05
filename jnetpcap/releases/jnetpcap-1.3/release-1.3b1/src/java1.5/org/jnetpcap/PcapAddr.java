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
package org.jnetpcap;

import java.util.ArrayList;
import java.util.List;

/**
 * Class peered with native <code>pcap_addr</code> structure. Holds pcap
 * addresses.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class PcapAddr {

	private native static void initIDs();

	static {
		initIDs();

		try {
			Class.forName("org.jnetpcap.PcapSockAddr");
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException(e);
		}

	}

	private volatile PcapAddr next;

	private volatile PcapSockAddr addr;

	private volatile PcapSockAddr netmask;

	private volatile PcapSockAddr broadaddr;

	private volatile PcapSockAddr dstaddr;

	/**
	 * @return the next
	 */
	@SuppressWarnings("unused")
	private final PcapAddr getNext() {
		return this.next;
	}

	/**
	 * pcap_addr.addr field.
	 * 
	 * @return the addr
	 */
	public final PcapSockAddr getAddr() {
		return this.addr;
	}

	/**
	 * pcap_addr.netmask field.
	 * 
	 * @return the netmask
	 */
	public final PcapSockAddr getNetmask() {
		return this.netmask;
	}

	/**
	 * pcap_addr.broadaddr field.
	 * 
	 * @return the broadaddr
	 */
	public final PcapSockAddr getBroadaddr() {
		return this.broadaddr;
	}

	/**
	 * pcap_addr.dstaddr field.
	 * 
	 * @return the dstaddr
	 */
	public final PcapSockAddr getDstaddr() {
		return this.dstaddr;
	}

	@SuppressWarnings( {
	    "unchecked",
	    "unused" })
	private List toList() {

		/**
		 * Don't use generics to keep compatiblity pre 1.5
		 */
		List list = new ArrayList();

		PcapAddr i = this;

		while (i != null) {
			list.add(i);

			i = i.next;
		}

		return list;
	}

	/**
	 * Debug information about this address object.
	 * 
	 * @return debug info
	 */
	@Override
	public String toString() {
		StringBuilder out = new StringBuilder();

		out.append("[");
		out.append("addr=").append(String.valueOf(addr));
		out.append(", mask=").append(String.valueOf(netmask));
		out.append(", broadcast=").append(String.valueOf(broadaddr));
		out.append(", dstaddr=").append(String.valueOf(dstaddr));
		out.append("]");

		return out.toString();
	}

}
