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
    extends
    JStruct {

	private static final String STRUCT_NAME = "scan_t";

	/**
	 * Special header ID that when used with a scanner's next_id variable,
	 * indicates that this is the last header and scanner should exit its loop.
	 * The constant can be used both in java and in JNI code.
	 */
	public final static int END_OF_HEADERS_ID = -1;

	/**
	 * Alocates and creates scan_t structure in native memory
	 */
	public JScan() {
		super(STRUCT_NAME, Type.PEER);
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
	
	public native int scan_prefix();
	
	public native int scan_gap();
	
	public native int scan_payload();
	
	public native int scan_postix();

	public native int record_header();

	
	public native void scan_prefix(int value);
	
	public native void scan_gap(int value);
	
	public native void scan_payload(int value);
	
	public native void scan_postix(int value);

	public native void record_header(int value);

	/**
	 * Sets all the various lengths in the header structure all at once
	 * 
	 * @param prefix
	 *          prefix length in bytes before the header
	 * @param header
	 *          length of the header (same as {@link #scan_length(int)})
	 * @param gap
	 *          length of the gap between header and payload
	 * @param payload
	 *          length of payload
	 * @param postfix
	 *          length of postfix after the payload
	 */
	public native void scan_set_lengths(
	    int prefix,
	    int header,
	    int gap,
	    int payload,
	    int postfix);

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
