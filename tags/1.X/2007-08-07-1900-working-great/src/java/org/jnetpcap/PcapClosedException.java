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
 * Thrown if Pcap object is access after it has been closed.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapClosedException
    extends IllegalStateException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 4803545074835523202L;

	/**
	 * 
	 */
	public PcapClosedException() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 */
	public PcapClosedException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param s
	 */
	public PcapClosedException(String s) {
		super(s);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param cause
	 */
	public PcapClosedException(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

}
