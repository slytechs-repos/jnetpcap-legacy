/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap;

// TODO: Auto-generated Javadoc
/**
 * The Class PcapStat.
 */
public class PcapStat {

	/**
	 * Inits the i ds.
	 */
	private static native void initIDs();

	static {
		System.loadLibrary(Pcap.JNETPCAP_LIBRARY_NAME);
		initIDs();
	}

	/** The Constant out. */
	protected final static StringBuilder out = new StringBuilder();

	/** The recv. */
	private long recv;

	/** The drop. */
	private long drop;

	/** The if drop. */
	private long ifDrop;

	/*
	 * The rest of the fields are only filled in by a call to WinPcap.statsEx
	 * which returns a subclass of PcapStat called WinPcapStat. The fields are
	 * only accessible from WinPcapStat class.
	 */

	/** The capt. */
	protected long capt;

	/** The sent. */
	protected long sent;

	/** The netdrop. */
	protected long netdrop;

	/**
	 * Gets the number of packets received.
	 * 
	 * @return the number of packets received
	 */
	public final long getRecv() {
		return this.recv;
	}

	/**
	 * Gets the number of packets dropped.
	 * 
	 * @return the number of packets dropped
	 */
	public final long getDrop() {
		return this.drop;
	}

	/**
	 * Gets the drops by interface XXX not yet supported.
	 * 
	 * @return the drops by interface XXX not yet supported
	 */
	public final long getIfDrop() {
		return this.ifDrop;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
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
