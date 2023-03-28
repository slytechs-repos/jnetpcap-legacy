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
package org.jnetpcap.nap;

import org.jnetpcap.nio.JMemory;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Nap
    extends
    JMemory {
	
	public static class Record {
		
	}

	public native static int sizeof();

	/**
	 * @param size
	 */
	private Nap(int size) {
		super(size);
	}
	
	public static Nap create(String file, StringBuilder errbuf) {
		Nap nap = new Nap(sizeof());

		nap.nativeOpen(file, "w+", errbuf);
		return nap;
	}


	public static Nap open(String file, StringBuilder errbuf) {
		Nap nap = new Nap(sizeof());

		nap.nativeOpen(file, "r+", errbuf);
		return nap;
	}

	/**
	 * @param file
	 * @param string
	 * @param errbuf
	 */
	private native void nativeOpen(
	    String file,
	    String mode,
	    StringBuilder errbuf);

}
