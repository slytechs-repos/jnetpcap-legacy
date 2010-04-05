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

/**
 * Class peered with native <code>pcap_stat</code> structure providing only
 * the core statistics. Class that is filled in by a call to method
 * <code>Pcap.stats</code>. The structure keeps statisical values on an
 * interface.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapStat {

	private static native void initIDs();

	static {
		System.loadLibrary(Pcap.JNETPCAP_LIBRARY_NAME);
		initIDs();
	}

	/**
	 * For toString() to build its string. Should be made thread local.
	 */
	protected final static StringBuilder out = new StringBuilder();

	/**
	 * number of packets received
	 */
	private long recv;

	/**
	 * number of packets dropped
	 */
	private long drop;

	/**
	 * drops by interface XXX not yet supported
	 */
	private long ifDrop;

	/*
	 * The rest of the fields are only filled in by a call to WinPcap.statsEx
	 * which returns a subclass of PcapStat called WinPcapStat. The fields are
	 * only accessible from WinPcapStat class.
	 */

	/**
	 * number of packets that are received by the application
	 */
	protected long capt;

	/**
	 * number of packets sent by the server on the network
	 */
	protected long sent;

	/**
	 * number of packets lost on the network
	 */
	protected long netdrop;

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

	/**
	 * Debug string
	 * return debug string
	 */
	@Override
  public String toString() {
		out.setLength(0);

		out.append("recv=").append(recv);
		out.append(", drop=").append(drop);
		out.append(", ifdrop=").append(ifDrop);

		return out.toString();
	}
}
