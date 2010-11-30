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

/**
 * Class peered with native <code>pcap_samp</code> structure. This class can
 * change the capture algorithm used by WinPcap. By changing the values within
 * this specially peered object, before any capture takes place, you can
 * influence the sampling algorithm used during capture.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class WinPcapSamp {

	private native static void initIDs(); // Initialize JNI

	private volatile long physical;

	static {
		initIDs();
	}

	/**
	 * This constructor called from JNI to initialize new object
	 * 
	 * @param addr
	 *          physical address of pcap_samp structure
	 */
	private WinPcapSamp(long addr) {
		this.physical = addr;
	}

	/**
	 * No sampling has to be done on the current capture. In this case, no
	 * sampling algorithms are applied to the current capture.
	 */
	public final static int NO_SAMP = 0;

	/**
	 * It defines that only 1 out of N packets must be returned to the user. In
	 * this case, the 'value' field of the 'pcap_samp' structure indicates the
	 * number of packets (minus 1) that must be discarded before one packet got
	 * accepted. In other words, if 'value = 10', the first packet is returned to
	 * the caller, while the following 9 are discarded.
	 */
	public final static int ONE_EVERY_N = 1;

	/**
	 * It defines that we have to return 1 packet every N milliseconds. In this
	 * case, the 'value' field of the 'WinPcapSamp' class indicates the 'waiting
	 * time' in milliseconds before one packet got accepted. In other words, if
	 * 'value = 10', the first packet is returned to the caller; the next returned
	 * one will be the first packet that arrives when 10ms have elapsed.
	 */
	public final static int FIRST_AFTER_N_MS = 2;

	/**
	 * Gets the current method type for capture sampling.
	 * 
	 * @return the return value specifies the sampling type:
	 *         <ul>
	 *         <li> 0 - {@link #NO_SAMP} - No sampling has to be done on the
	 *         current capture</li>
	 *         <li> 1 - {@link #ONE_EVERY_N} - only 1 out of N packets must be
	 *         returned to the user</li>
	 *         <li> 2 - {@link #FIRST_AFTER_N_MS} - return 1 packet every N
	 *         milliseconds</li>
	 *         </ul>
	 */
	public native int getMethod();

	/**
	 * Sets the current method type for capturing sampling. The algorithm is
	 * changed for the current capture, as long as no packets have been captured
	 * or entered any dispatchable loops.
	 * 
	 * @param method
	 *          sampling type:
	 *          <ul>
	 *          <li> 0 - {@link #NO_SAMP} - No sampling has to be done on the
	 *          current capture</li>
	 *          <li> 1 - {@link #ONE_EVERY_N} - only 1 out of N packets must be
	 *          returned to the user</li>
	 *          <li> 2 - {@link #FIRST_AFTER_N_MS} - return 1 packet every N
	 *          milliseconds</li>
	 *          </ul>
	 */
	public native void setMethod(int method);

	/**
	 * This value depends on the sampling method defined.
	 * 
	 * @return this value depends on the sampling method defined
	 */
	public native int getValue();

	/**
	 * Sets the value. this value depends on the sampling method defined.
	 * 
	 * @param value
	 *          new value; this value depends on the sampling method defined
	 */
	public native void setValue(int value);

	/**
	 * Returns the current values of this object as strings.
	 */
	public String toString() {
		return "method:" + getMethod() + ", value:" + getValue();
	}

}
