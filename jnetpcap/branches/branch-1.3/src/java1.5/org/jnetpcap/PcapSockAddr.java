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
 * The Class PcapSockAddr.
 */
public class PcapSockAddr {

	/**
	 * Inits the i ds.
	 */
	private native static void initIDs();

	static {
		initIDs();
	}

	/** The Constant AF_INET. */
	public final static int AF_INET = 2;

	/** The Constant AF_INET6. */
	public final static int AF_INET6 = 23;

	/** The family. */
	private volatile short family;

	/** The data. */
	private volatile byte[] data;

	/**
	 * Gets the family.
	 * 
	 * @return the family
	 */
	public final short getFamily() {
		return this.family;
	}

	/**
	 * Gets the data.
	 * 
	 * @return the data
	 */
	public final byte[] getData() {
		return this.data;
	}

	/**
	 * U.
	 * 
	 * @param b
	 *          the b
	 * @return the int
	 */
	private int u(byte b) {
		return (b >= 0) ? b : b + 256;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
  public String toString() {
		switch (family) {
			case AF_INET:
				return "[INET4:" + u(data[0]) + "." + u(data[1]) + "." + u(data[2])
				    + "." + u(data[3]) + "]";

			case AF_INET6:
				return "[INET6:" + data[0] + "." + data[1] + "." + data[2] + "."
				    + data[3] + "]";

			default:
				return "[" + family + "]";
		}

	}
}
