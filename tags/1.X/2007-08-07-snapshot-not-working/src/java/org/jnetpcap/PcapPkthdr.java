/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
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

/**
 * A class that is bound to Libpcap <code>pcap_pkthdr</code> structure. This
 * classes fields are initialized with values from the C structure. There are no
 * setter methods, since the <code>pcap_pkthdr</code> C structure is used in
 * read-only fassion.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapPkthdr {

	private volatile long seconds;

	private volatile int useconds;

	private volatile int caplen;

	private volatile int len;

	/**
	 * Capture timestamp in seconds.
	 * 
	 * @return the seconds
	 */
	public final long getSeconds() {
		return this.seconds;
	}

	/**
	 * Capture timestamp in microseconds fraction.
	 * 
	 * @return the useconds
	 */
	public final int getUseconds() {
		return this.useconds;
	}

	/**
	 * Number of bytes actually captured.
	 * 
	 * @return the caplen
	 */
	public final int getCaplen() {
		return this.caplen;
	}

	/**
	 * Number of original bytes in the packet.
	 * 
	 * @return the len
	 */
	public final int getLen() {
		return this.len;
	}

}
