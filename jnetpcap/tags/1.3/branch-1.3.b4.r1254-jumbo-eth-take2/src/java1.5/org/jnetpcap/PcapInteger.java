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

import org.jnetpcap.nio.JNumber;

// TODO: Auto-generated Javadoc
/**
 * The Class PcapInteger.
 */
public final class PcapInteger {

	/** The value. */
	private volatile int value;

	/**
	 * Instantiates a new pcap integer.
	 * 
	 * @param value
	 *          the value
	 */
	public PcapInteger(int value) {
		this.value = value;
	}

	/**
	 * Instantiates a new pcap integer.
	 */
	public PcapInteger() {
		this.value = 0;
	}

	/**
	 * Gets the modified from JNI methods.
	 * 
	 * @return the modified from JNI methods
	 */
	public final int getValue() {
		return this.value;
	}

	/**
	 * Sets the modified from JNI methods.
	 * 
	 * @param value
	 *          the new modified from JNI methods
	 */
	public final void setValue(int value) {
		this.value = value;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
  public String toString() {
		return Integer.toString(value);
	}
}
