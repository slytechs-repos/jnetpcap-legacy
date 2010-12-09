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
 * The Class PcapPktHdr.
 */
public class PcapPktHdr {

	/**
	 * Inits the i ds.
	 */
	private native static void initIDs();

	static {
		initIDs();
	}

	/** The seconds. */
	private volatile long seconds;

	/** The useconds. */
	private volatile int useconds;

	/** The caplen. */
	private volatile int caplen;

	/** The len. */
	private volatile int len;

	/**
	 * Instantiates a new pcap pkt hdr.
	 */
	public PcapPktHdr() {
		this.seconds = System.currentTimeMillis() / 1000; // In seconds
		this.useconds = (int) (System.nanoTime() / 1000); // Microseconds

		this.caplen = 0;
		this.len = 0;
	}

	/**
	 * Instantiates a new pcap pkt hdr.
	 * 
	 * @param caplen
	 *          the caplen
	 * @param len
	 *          the len
	 */
	public PcapPktHdr(int caplen, int len) {
		this.caplen = caplen;
		this.len = len;

		this.seconds = System.currentTimeMillis() / 1000; // In seconds
		this.useconds = (int) (System.nanoTime() / 1000); // Microseconds
	}

	/**
	 * Instantiates a new pcap pkt hdr.
	 * 
	 * @param seconds
	 *          the seconds
	 * @param useconds
	 *          the useconds
	 * @param caplen
	 *          the caplen
	 * @param len
	 *          the len
	 */
	public PcapPktHdr(long seconds, int useconds, int caplen, int len) {
		this.seconds = seconds;
		this.useconds = useconds;
		this.caplen = caplen;
		this.len = len;
	}

	/**
	 * Gets the seconds.
	 * 
	 * @return the seconds
	 */
	public final long getSeconds() {
		return this.seconds;
	}

	/**
	 * Gets the useconds.
	 * 
	 * @return the useconds
	 */
	public final int getUseconds() {
		return this.useconds;
	}

	/**
	 * Gets the caplen.
	 * 
	 * @return the caplen
	 */
	public final int getCaplen() {
		return this.caplen;
	}

	/**
	 * Gets the len.
	 * 
	 * @return the len
	 */
	public final int getLen() {
		return this.len;
	}

	/**
	 * Sets the seconds.
	 * 
	 * @param seconds
	 *          the new seconds
	 */
	public final void setSeconds(long seconds) {
		this.seconds = seconds;
	}

	/**
	 * Sets the useconds.
	 * 
	 * @param useconds
	 *          the new useconds
	 */
	public final void setUseconds(int useconds) {
		this.useconds = useconds;
	}

	/**
	 * Sets the caplen.
	 * 
	 * @param caplen
	 *          the new caplen
	 */
	public final void setCaplen(int caplen) {
		this.caplen = caplen;
	}

	/**
	 * Sets the len.
	 * 
	 * @param len
	 *          the new len
	 */
	public final void setLen(int len) {
		this.len = len;
	}

}
