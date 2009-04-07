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
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JScan
    extends JStruct {

	private static final String STRUCT_NAME = "scan_t";

	/**
	 * @param structName
	 */
	public JScan() {
		super(STRUCT_NAME);
	}

	protected native int scan_id();

	protected native int scan_next_id();

	protected native int scan_length();

	protected native void scan_id(int id);

	protected native void scan_next_id(int next_id);

	protected native void scan_length(int length);

	/**
   * @param buffer
   */
  public native void scan_buf(JBuffer buffer);

	/**
   * @param size
   */
  public native void scan_buf_len(int size);

	/**
   * @param offset
   */
  public native void scan_offset(int offset);

	/**
   * @return
   */
  public native JPacket scan_packet();

	/**
   * @return
   */
  public native int scan_offset();
}
