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
package org.jnetpcap;

import org.jnetpcap.nio.JStruct;
import org.jnetpcap.packet.JCaptureHeader;

/**
 * <pre>
 * struct pkt_header {
 *  struct timeval ts; // ts.tv_sec, ts.tv_usec
 *  uint32 caplen;     // captured length
 *  uint32 len;        // original length
 * }
 * </pre>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapHeader
    extends JStruct implements JCaptureHeader {

	public static final String STRUCT_NAME = "pkt_header";

	/**
	 * 
	 */
  public PcapHeader() {
	  super(STRUCT_NAME);
  }


	public native long sec();

	public native int usec();

	public native int len();

	public native int wirelen();


	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#fullLength()
	 */
	public int fullLength() {
		return wirelen();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#nanos()
	 */
	public long nanos() {
		return usec() * 1000;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#truncatedLength()
	 */
	public int truncatedLength() {
		return len();
	}

	/* (non-Javadoc)
   * @see org.jnetpcap.packet.JCaptureHeader#seconds()
   */
  public long seconds() {
	  return sec();
  }

}