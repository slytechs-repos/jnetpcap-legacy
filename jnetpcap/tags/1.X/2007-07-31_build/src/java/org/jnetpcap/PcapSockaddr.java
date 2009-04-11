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
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapSockaddr {

	public final static int AF_INET = 2;

	public final static int AF_INET6 = 23;

	private short family;

	private byte[] data;

	/**
	 * @return the family
	 */
	public final short getFamily() {
		return this.family;
	}

	/**
	 * @return the data
	 */
	public final byte[] getData() {
		return this.data;
	}
	
	private int u(byte b) {
		return (b >= 0)?b:b + 256;
	}

	public String toString() {
		switch (family) {
			case AF_INET:
				return "[INET4:" + u(data[0]) + "." + u(data[1]) + "." + u(data[2]) + "."
				    + u(data[3]) + "]";

			case AF_INET6:
				return "[INET6:" + data[0] + "." + data[1] + "." + data[2] + "."
				    + data[3] + "]";

			default:
				return "[" + family + "]";
		}

	}
}
