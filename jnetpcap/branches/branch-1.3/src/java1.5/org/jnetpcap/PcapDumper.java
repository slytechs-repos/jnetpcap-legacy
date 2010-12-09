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

import java.nio.ByteBuffer;

import org.jnetpcap.nio.JBuffer;

// TODO: Auto-generated Javadoc
/**
 * The Class PcapDumper.
 */
public class PcapDumper {

	/** The physical. */
	private volatile long physical;

	/**
	 * Inits the i ds.
	 */
	private static native void initIDs();

	static {
		initIDs();
	}

	/**
	 * Dump.
	 * 
	 * @param hdr
	 *          the hdr
	 * @param packet
	 *          the packet
	 */
	public void dump(PcapPktHdr hdr, ByteBuffer packet) {
		dump(hdr.getSeconds(), hdr.getUseconds(), hdr.getCaplen(), hdr.getLen(),
		    packet);
	}

	/**
	 * Dump.
	 * 
	 * @param hdr
	 *          the hdr
	 * @param packet
	 *          the packet
	 */
	public native void dump(PcapHeader hdr, ByteBuffer packet);

	/**
	 * Dump.
	 * 
	 * @param hdr
	 *          the hdr
	 * @param packet
	 *          the packet
	 */
	public native void dump(PcapHeader hdr, JBuffer packet);

	/**
	 * Dump.
	 * 
	 * @param seconds
	 *          the seconds
	 * @param useconds
	 *          the useconds
	 * @param caplen
	 *          the caplen
	 * @param len
	 *          the len
	 * @param packet
	 *          the packet
	 */
	public native void dump(long seconds, int useconds, int caplen, int len,
	    ByteBuffer packet);

	/**
	 * Ftell.
	 * 
	 * @return the long
	 */
	public native long ftell();

	/**
	 * Flush.
	 * 
	 * @return the int
	 */
	public native int flush();

	/**
	 * Close.
	 */
	public native void close();

}
