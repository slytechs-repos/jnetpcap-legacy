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
    extends JCaptureHeader {

	public static final String STRUCT_NAME = "pcap_pkthdr";

	/**
	 * 
	 */
	public PcapHeader() {
		super(STRUCT_NAME);
	}

	private native long hdr_sec();

	private native int hdr_usec();

	private native int hdr_len();

	private native int hdr_wirelen();

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#fullLength()
	 */
	public int wirelen() {
		return hdr_wirelen();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#nanos()
	 */
	public long nanos() {
		return hdr_usec() * 1000;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#truncatedLength()
	 */
	public int caplen() {
		return hdr_len();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#seconds()
	 */
	public long seconds() {
		return hdr_sec();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#transferTo(org.jnetpcap.packet.JCaptureHeader)
	 */
	@Override
	public <T extends JCaptureHeader> int transferTo(T hdr) {
		if (hdr.getStructName() == STRUCT_NAME) {
			return peer(hdr);
		} else {
			throw new IllegalArgumentException("Can not peer non PcapHeader objects");
		}
	}

}