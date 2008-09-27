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
 * Class peered with native <code>pcap_pkthdr</code> structure. This classes
 * fields are initialized with values from the C structure. There are no setter
 * methods, since the <code>pcap_pkthdr</code> C structure is used in
 * read-only fassion.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapPktHdr {

	private native static void initIDs();

	static {
		initIDs();
	}

	private volatile long seconds;

	private volatile int useconds;

	private volatile int caplen;

	private volatile int len;

	/**
	 * Initializes the timestamp fields to current time and length fields to 0.
	 */
	public PcapPktHdr() {
		this.seconds = System.currentTimeMillis() / 1000; // In seconds
		this.useconds = (int) (System.currentTimeMillis() * 1000); // Microseconds

		this.caplen = 0;
		this.len = 0;
	}

	/**
	 * Allocates a new packet header and initializes the caplen and len fields.
	 * The timestamp fields are initialized to current timestamp.
	 * 
	 * @param caplen
	 *          amount of data captured
	 * @param len
	 *          original packet length
	 */
	public PcapPktHdr(int caplen, int len) {
		this.caplen = caplen;
		this.len = len;

		this.seconds = System.currentTimeMillis() / 1000; // In seconds
		this.useconds = (int) (System.currentTimeMillis() * 1000); // Microseconds
	}

	/**
	 * @param seconds
	 *          time stamp in seconds
	 * @param useconds
	 *          a fraction of a second. Valid value is from 0 to 999,999.
	 * @param caplen
	 *          amount of data captured
	 * @param len
	 *          original packet length
	 */
	public PcapPktHdr(long seconds, int useconds, int caplen, int len) {
		this.seconds = seconds;
		this.useconds = useconds;
		this.caplen = caplen;
		this.len = len;
	}

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

	/**
	 * @param seconds
	 *          the seconds to set
	 */
	public final void setSeconds(long seconds) {
		this.seconds = seconds;
	}

	/**
	 * @param useconds
	 *          the useconds to set
	 */
	public final void setUseconds(int useconds) {
		this.useconds = useconds;
	}

	/**
	 * @param caplen
	 *          the caplen to set
	 */
	public final void setCaplen(int caplen) {
		this.caplen = caplen;
	}

	/**
	 * @param len
	 *          the len to set
	 */
	public final void setLen(int len) {
		this.len = len;
	}

}
