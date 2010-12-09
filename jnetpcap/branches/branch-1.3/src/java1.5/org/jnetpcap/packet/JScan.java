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
package org.jnetpcap.packet;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;

// TODO: Auto-generated Javadoc
/**
 * The Class JScan.
 */
public class JScan
    extends
    JStruct {

	/** The Constant STRUCT_NAME. */
	private static final String STRUCT_NAME = "scan_t";

	/** The Constant END_OF_HEADERS_ID. */
	public final static int END_OF_HEADERS_ID = -1;

	/**
	 * Instantiates a new j scan.
	 */
	public JScan() {
		super(STRUCT_NAME, sizeof());
	}

	/**
	 * Instantiates a new j scan.
	 * 
	 * @param type
	 *          the type
	 */
	public JScan(Type type) {
		super(STRUCT_NAME, type);
	}

	/**
	 * Scan_id.
	 * 
	 * @return the int
	 */
	public native int scan_id();

	/**
	 * Scan_next_id.
	 * 
	 * @return the int
	 */
	public native int scan_next_id();

	/**
	 * Scan_length.
	 * 
	 * @return the int
	 */
	public native int scan_length();

	/**
	 * Scan_id.
	 * 
	 * @param id
	 *          the id
	 */
	public native void scan_id(int id);

	/**
	 * Scan_next_id.
	 * 
	 * @param next_id
	 *          the next_id
	 */
	public native void scan_next_id(int next_id);

	/**
	 * Scan_length.
	 * 
	 * @param length
	 *          the length
	 */
	public native void scan_length(int length);
	
	/**
	 * Scan_prefix.
	 * 
	 * @return the int
	 */
	public native int scan_prefix();
	
	/**
	 * Scan_gap.
	 * 
	 * @return the int
	 */
	public native int scan_gap();
	
	/**
	 * Scan_payload.
	 * 
	 * @return the int
	 */
	public native int scan_payload();
	
	/**
	 * Scan_postix.
	 * 
	 * @return the int
	 */
	public native int scan_postix();

	/**
	 * Record_header.
	 * 
	 * @return the int
	 */
	public native int record_header();

	
	/**
	 * Scan_prefix.
	 * 
	 * @param value
	 *          the value
	 */
	public native void scan_prefix(int value);
	
	/**
	 * Scan_gap.
	 * 
	 * @param value
	 *          the value
	 */
	public native void scan_gap(int value);
	
	/**
	 * Scan_payload.
	 * 
	 * @param value
	 *          the value
	 */
	public native void scan_payload(int value);
	
	/**
	 * Scan_postix.
	 * 
	 * @param value
	 *          the value
	 */
	public native void scan_postix(int value);

	/**
	 * Record_header.
	 * 
	 * @param value
	 *          the value
	 */
	public native void record_header(int value);

	/**
	 * Scan_set_lengths.
	 * 
	 * @param prefix
	 *          the prefix
	 * @param header
	 *          the header
	 * @param gap
	 *          the gap
	 * @param payload
	 *          the payload
	 * @param postfix
	 *          the postfix
	 */
	public native void scan_set_lengths(
	    int prefix,
	    int header,
	    int gap,
	    int payload,
	    int postfix);

	/**
	 * Sizeof.
	 * 
	 * @return the int
	 */
	public native static int sizeof();

	/**
	 * Scan_buf.
	 * 
	 * @param buffer
	 *          the buffer
	 */
	public native void scan_buf(JBuffer buffer);

	/**
	 * Scan_buf_len.
	 * 
	 * @param size
	 *          the size
	 */
	public native void scan_buf_len(int size);

	/**
	 * Scan_offset.
	 * 
	 * @param offset
	 *          the offset
	 */
	public native void scan_offset(int offset);

	/**
	 * Scan_packet.
	 * 
	 * @return the j packet
	 */
	public native JPacket scan_packet();

	/**
	 * Scan_offset.
	 * 
	 * @return the int
	 */
	public native int scan_offset();
}
