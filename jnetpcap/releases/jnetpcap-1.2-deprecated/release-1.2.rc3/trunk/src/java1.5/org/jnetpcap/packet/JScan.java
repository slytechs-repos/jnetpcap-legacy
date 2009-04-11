/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.packet;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;

/**
 * A inprogress working scan structure. Used by JScanner to pass around
 * information between various scan routines. This class is peered with scan_t
 * structure that is used to pass information both between native header
 * scanners and java scanners.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JScan
    extends JStruct {

	private static final String STRUCT_NAME = "scan_t";

	/**
	 * Alocates and creates scan_t structure in native memory
	 */
	public JScan() {
		super(STRUCT_NAME, sizeof());
	}

	/**
	 * Creates an uninitialized scan structure
	 * 
	 * @param type
	 *          memory type
	 */
	public JScan(Type type) {
		super(STRUCT_NAME, type);
	}

	public native int scan_id();

	public native int scan_next_id();

	public native int scan_length();

	public native void scan_id(int id);

	public native void scan_next_id(int next_id);

	public native void scan_length(int length);

	/**
	 * Size in bytes of the native scan_t structure on this particular platform
	 * 
	 * @return size in bytes
	 */
	public native static int sizeof();

	/**
	 * Gets the current packet data buffer
	 * 
	 * @param buffer
	 *          packet data buffer
	 */
	public native void scan_buf(JBuffer buffer);

	/**
	 * Size of packet data
	 * 
	 * @param size
	 *          length in bytes
	 */
	public native void scan_buf_len(int size);

	/**
	 * Sets the current offset by the scanner into the packet buffer
	 * 
	 * @param offset
	 *          offset in bytes
	 */
	public native void scan_offset(int offset);

	/**
	 * Java packet that is being processed
	 * 
	 * @return the packet instance being currently processed
	 */
	public native JPacket scan_packet();

	/**
	 * Gets teh curren offset by the dscanner into the packet buffer
	 * 
	 * @return offset in bytes
	 */
	public native int scan_offset();
}
