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
package org.jnetpcap;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;

// TODO: Auto-generated Javadoc
/**
 * The Class PcapHeader.
 */
public class PcapHeader
    extends
    JStruct implements JCaptureHeader {

	/** The Constant STRUCT_NAME. */
	public static final String STRUCT_NAME = "pcap_pkthdr";

	/**
	 * Sizeof.
	 * 
	 * @return the int
	 */
	public native static int sizeof();

	/** The Constant LENGTH. */
	public final static int LENGTH = 16;

	/**
	 * Instantiates a new pcap header.
	 */
	public PcapHeader() {
		super(STRUCT_NAME, LENGTH);
	}

	/**
	 * Instantiates a new pcap header.
	 * 
	 * @param caplen
	 *          the caplen
	 * @param wirelen
	 *          the wirelen
	 */
	public PcapHeader(int caplen, int wirelen) {
		super(STRUCT_NAME, LENGTH);

		hdr_len(caplen);
		hdr_wirelen(wirelen);

		long t = System.currentTimeMillis();
		long s = t / 1000;
		long us = (t - s * 1000) * 1000;

		hdr_sec(s);
		hdr_usec((int) us);
	}

	/**
	 * Instantiates a new pcap header.
	 * 
	 * @param type
	 *          the type
	 */
	public PcapHeader(Type type) {
		super(STRUCT_NAME, type);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#caplen()
	 */
	public int caplen() {
		return hdr_len();
	}

	/**
	 * Hdr_len.
	 * 
	 * @return the int
	 */
	public native int hdr_len();

	/**
	 * Hdr_len.
	 * 
	 * @param len
	 *          the len
	 */
	public native void hdr_len(int len);

	/**
	 * Hdr_sec.
	 * 
	 * @return the long
	 */
	public native long hdr_sec();

	/**
	 * Hdr_sec.
	 * 
	 * @param ts
	 *          the ts
	 */
	public native void hdr_sec(long ts);

	/**
	 * Hdr_usec.
	 * 
	 * @return the int
	 */
	public native int hdr_usec();

	/**
	 * Hdr_usec.
	 * 
	 * @param ts
	 *          the ts
	 */
	public native void hdr_usec(int ts);

	/**
	 * Hdr_wirelen.
	 * 
	 * @return the int
	 */
	public native int hdr_wirelen();

	/**
	 * Hdr_wirelen.
	 * 
	 * @param len
	 *          the len
	 */
	public native void hdr_wirelen(int len);

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#nanos()
	 */
	public long nanos() {
		return hdr_usec() * 1000;
	}

	/**
	 * Peer.
	 * 
	 * @param memory
	 *          the memory
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int peer(JBuffer memory, int offset) {
		return super.peer(memory, offset, sizeof());
	}

	/**
	 * Peer to.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int peerTo(JBuffer buffer, int offset) {
		return super.peer(buffer, offset, sizeof());
	}

	/**
	 * Peer to.
	 * 
	 * @param header
	 *          the header
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int peerTo(PcapHeader header, int offset) {
		return super.peer(header, offset, header.size());
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#seconds()
	 */
	public long seconds() {
		return hdr_sec();
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#timestampInMillis()
	 */
	public long timestampInMillis() {
		long l = hdr_sec() * 1000 + hdr_usec() / 1000;

		return l;
	}

	/**
	 * Transfer to.
	 * 
	 * @param m
	 *          the m
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int transferTo(JBuffer m, int offset) {
		return super.transferTo(m, 0, size(), offset);
	}

	/**
	 * Transfer to.
	 * 
	 * @param m
	 *          the m
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int transferTo(byte[] m, int offset) {
		return super.transferTo(m, 0, size(), offset);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#wirelen()
	 */
	public int wirelen() {
		return hdr_wirelen();
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#caplen(int)
	 */
	public void caplen(int caplen) {
		throw new UnsupportedOperationException("Not allowed on PcapHeader");
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#nanos(long)
	 */
	public void nanos(long nanos) {
		throw new UnsupportedOperationException("Not allowed on PcapHeader");
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#seconds(long)
	 */
	public void seconds(long seconds) {
		throw new UnsupportedOperationException("Not allowed on PcapHeader");
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#wirelen(int)
	 */
	public void wirelen(int wirelen) {
		throw new UnsupportedOperationException("Not allowed on PcapHeader");
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#initFrom(org.jnetpcap.JCaptureHeader)
	 */
	public void initFrom(JCaptureHeader captureHeader) {
		throw new UnsupportedOperationException("Not allowed on PcapHeader");
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#timestampInNanos()
	 */
	public long timestampInNanos() {
		return hdr_sec() * 1000000000 + hdr_usec() * 1000;
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.JCaptureHeader#timestampInMicros()
	 */
	public long timestampInMicros() {
		return hdr_sec() * 1000000 + hdr_usec();
	}

}