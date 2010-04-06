/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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

import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;

/**
 * A raw pcap packet record. The record consists of a single memory segment that
 * has the following data structures; a pcap header followed by packet data:
 * 
 * <pre>
 * [header][data]
 * </pre>
 * 
 * The pcap header length is constant, while the data is not and is determined
 * by the caplen field within the header.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapRecord
    extends
    JBuffer {

	/**
	 * @param type
	 */
	public PcapRecord(Type type) {
		super(type);
	}

	public PcapHeader getHeader() {
		return getHeader(new PcapHeader(Type.POINTER));
	}

	public PcapHeader getHeader(PcapHeader header) {
		throw new UnsupportedOperationException();
	}

	public JBuffer getDataBuffer() {
		return getDataBuffer(new JBuffer(Type.POINTER));
	}

	public JBuffer getDataBuffer(JBuffer buffer) {
		throw new UnsupportedOperationException();
	}
	
	public final int getDataOffset() {
		return PcapHeader.LENGTH;
	}

	public final int getHeaderOffset() {
		return 0;
	}
	
	public final int getHeaderLength() {
		return PcapHeader.LENGTH;
	}
	
	public final int getDataLength() {
		return size() - PcapHeader.LENGTH;
	}
}
