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

// TODO: Auto-generated Javadoc
/**
 * The Class WinPcapSamp.
 */
public final class WinPcapSamp {

	/**
	 * Inits the i ds.
	 */
	private native static void initIDs(); // Initialize JNI

	/** The physical. */
	private volatile long physical;

	static {
		initIDs();
	}

	/**
	 * Instantiates a new win pcap samp.
	 * 
	 * @param addr
	 *          the addr
	 */
	private WinPcapSamp(long addr) {
		this.physical = addr;
	}

	/** The Constant NO_SAMP. */
	public final static int NO_SAMP = 0;

	/** The Constant ONE_EVERY_N. */
	public final static int ONE_EVERY_N = 1;

	/** The Constant FIRST_AFTER_N_MS. */
	public final static int FIRST_AFTER_N_MS = 2;

	/**
	 * Gets the method.
	 * 
	 * @return the method
	 */
	public native int getMethod();

	/**
	 * Sets the method.
	 * 
	 * @param method
	 *          the new method
	 */
	public native void setMethod(int method);

	/**
	 * Gets the value.
	 * 
	 * @return the value
	 */
	public native int getValue();

	/**
	 * Sets the value.
	 * 
	 * @param value
	 *          the new value
	 */
	public native void setValue(int value);

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return "method:" + getMethod() + ", value:" + getValue();
	}

}
