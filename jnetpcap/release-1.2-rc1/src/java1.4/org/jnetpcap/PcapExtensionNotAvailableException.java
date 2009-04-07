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
 * Exception is thrown when a pcap extension is accessed, one of its methods,
 * while it is not supported on this particular platform. You must use
 * appropriate <code>isSupported</code> method call that is available with the
 * extension (i.e. <code>WinPcap.isSupported()</code>).
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapExtensionNotAvailableException
    extends IllegalStateException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 4206020497547882412L;

	/**
	 * 
	 */
	public PcapExtensionNotAvailableException() {
		super();
	}

	/**
	 * @param s
	 */
	public PcapExtensionNotAvailableException(String s) {
		super(s);
	}

}
