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

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;

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

	public static final String STRUCT_NAME = "pcap_pkthdr";

	/**
	 * Size of the pcap_pkthdr structure in bytes.
	 * 
	 * @return size of structure
	 */
	public native static int sizeof();

	/**
	 * 
	 */
	public PcapHeader() {
		super(STRUCT_NAME, sizeof());
	}

	/**
	 * @param caplen
	 * @param wirelen
	 */
	public PcapHeader(int caplen, int wirelen) {
		super(STRUCT_NAME, sizeof());

		hdr_len(caplen);
		hdr_wirelen(wirelen);

		long t = System.currentTimeMillis();
		long s = t / 1000;
		long us = (t - s * 1000) * 1000;

		hdr_sec(s);
		hdr_usec((int) us);
	}

	public PcapHeader(Type type) {
		super(STRUCT_NAME, type);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#truncatedLength()
	 */
	public int caplen() {
		return hdr_len();
	}

	public native int hdr_len();

	public native void hdr_len(int len);

	public native long hdr_sec();

	public native void hdr_sec(long ts);

	public native int hdr_usec();

	public native void hdr_usec(int ts);

	public native int hdr_wirelen();

	public native void hdr_wirelen(int len);

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#nanos()
	 */
	public long nanos() {
		return hdr_usec() * 1000;
	}

	public int peer(JBuffer memory, int offset) {
		return super.peer(memory, offset, sizeof());
	}

	public int peerTo(JBuffer buffer, int offset) {
	  return super.peer(buffer, offset, sizeof());
  }

	public int peerTo(PcapHeader header, int offset) {
			return super.peer(header, offset, header.size());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#seconds()
	 */
	public long seconds() {
		return hdr_sec();
	}

	public long timestampInMillis() {
		long l = hdr_sec() * 1000 + hdr_usec() / 1000;

		return l;
	}

  public int transferTo(JBuffer m, int offset) {
		return super.transferTo(m, 0, size(), offset);
	}
  
  public int transferTo(byte[] m, int offset) {
		return super.transferTo(m, 0, size(), offset);
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JCaptureHeader#fullLength()
	 */
	public int wirelen() {
		return hdr_wirelen();
	}

}