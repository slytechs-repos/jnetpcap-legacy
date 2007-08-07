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
package org.jnetpcap.winpcap;

import org.jnetpcap.PcapStat;

/**
 * Provides access to additional statical fields as returned from a call to
 * WinPcap.statsEx().
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class WinPcapStat
    extends PcapStat {

	private native static void initIDs();

	static {
		initIDs();
	}

	/**
	 * number of packets that are received by the application
	 */
	public long getCapt() {
		return super.capt;
	}

	/**
	 * number of packets lost on the network
	 */
	public long getNetdrop() {
		return super.netdrop;
	}

	/**
	 * number of packets sent by the server on the network
	 */
	public long getSent() {
		return super.sent;
	}


	/**
	 * Dumps all the values as a string.
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
