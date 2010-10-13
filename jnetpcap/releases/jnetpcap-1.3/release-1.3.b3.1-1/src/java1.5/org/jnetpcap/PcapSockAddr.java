/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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
 * Class peered with native <code>struct sockaddr</code> structure. The class
 * contains the same fields of the counter part C structure. In jNetPcap library
 * its fields are initialized within the native library and returned to java
 * space. The class is readonly, and only provides getter methods.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapSockAddr {

	private native static void initIDs();

	static {
		initIDs();
	}

	/**
	 * Socket family internet version 4
	 */
	public final static int AF_INET = 2;

	/**
	 * Socket family internet version 6
	 */
	public final static int AF_INET6 = 23;

	private volatile short family;

	private volatile byte[] data;

	/**
	 * Gets the socket's protocol family identifier.
	 * 
	 * @return the family
	 */
	public final short getFamily() {
		return this.family;
	}

	/**
	 * Gets protocol family specifiy array of bytes which contain the protocol's
	 * address. Length of the byte[] is protocol type dependent.
	 * 
	 * @return the data
	 */
	public final byte[] getData() {
		return this.data;
	}

	private int u(byte b) {
		return (b >= 0) ? b : b + 256;
	}

	/**
	 * Debug string
	 * 
	 * @return debug string
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
