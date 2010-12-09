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
package org.jnetpcap.winpcap;

import org.jnetpcap.PcapStat;

// TODO: Auto-generated Javadoc
/**
 * The Class WinPcapStat.
 */
public class WinPcapStat
    extends PcapStat {

	/**
	 * Inits the i ds.
	 */
	private native static void initIDs();

	static {
		initIDs();
	}

	/**
	 * Instantiates a new win pcap stat.
	 */
	private WinPcapStat() {

	}

	/**
	 * Gets the capt.
	 * 
	 * @return the capt
	 */
	public long getCapt() {
		return super.capt;
	}

	/**
	 * Gets the netdrop.
	 * 
	 * @return the netdrop
	 */
	public long getNetdrop() {
		return super.netdrop;
	}

	/**
	 * Gets the sent.
	 * 
	 * @return the sent
	 */
	public long getSent() {
		return super.sent;
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.PcapStat#toString()
	 */
	public String toString() {

		out.setLength(0);

		out.append("recv=").append(getRecv());
		out.append(", drop=").append(getDrop());
		out.append(", ifdrop=").append(getIfDrop());
		out.append(", capt=").append(getCapt());
		out.append(", netdrop=").append(getNetdrop());
		out.append(", sent=").append(getSent());

		return out.toString();
	}
}
