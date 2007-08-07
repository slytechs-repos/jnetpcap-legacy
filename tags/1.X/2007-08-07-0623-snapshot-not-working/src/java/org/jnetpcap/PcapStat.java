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
 * Class that is filled in by a call to method <code>Pcap.stats</code>. The
 * structure keeps statisical values on an interface.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapStat {

	private static native void initIDs();

	static {
		initIDs();
	}

	private long recv;

	private long drop;

	private long ifDrop;

	/**
	 * This field is only accessible from subclass WinPcapStat.
	 */
	protected long capt;

	/**
	 * Number of packets transmitted on the network
	 * 
	 * @return the recv
	 */
	public final long getRecv() {
		return this.recv;
	}

	/**
	 * number of packets dropped by the driver
	 * 
	 * @return the drop
	 */
	public final long getDrop() {
		return this.drop;
	}

	/**
	 * drops by interface. Not supported.
	 * 
	 * @return the ifdrop
	 */
	public final long getIfDrop() {
		return this.ifDrop;
	}
	
	public String toString() {
		return "recv=" + recv + ", drop=" + drop + ", ifDrop=" + ifDrop; 
	}
}
