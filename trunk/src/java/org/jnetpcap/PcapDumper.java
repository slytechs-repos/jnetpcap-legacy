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
public class PcapDumper {

	private volatile long physical;

	private static native void initIDs();

	static {
		initIDs();
	}

	/**
	 * Returns the current file position for the "savefile", representing the
	 * number of bytes written by <code>Pcap.dumpOpen</code> and
	 * <code>Pcap.dump</code>.
	 * 
	 * @return position within the file, or -1 on error
	 */
	public native long ftell();

	/**
	 * Flushes the output buffer to the "savefile", so that any packets written
	 * with <code>Pcap.dump</code> but not yet written to the "savefile" will be
	 * written.
	 * 
	 * @return 0 on success, -1 on error
	 */
	public native int flush();

	/**
	 * Closes a savefile. The existing PcapDumper object on which close method was
	 * invoked is no longer usable and needs to be discarded.
	 */
	public native void close();

}
