/**
 * $Id$
 * Copyright (C) 2006 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jnetpcap;

/**
 * This interface accesses data returned by the PCAP library after a packet
 * capture. You can access the packet header as returned and filled in by
 * PCAP library and access the raw data of the packet in form of a byte[]
 * 
 * @author Mark Bednarczyk
 */
public interface PcapPacket {

	/**
	 * PCAP library header packet header describing the capture event
	 * at the time the packet was captured.
	 * 
	 * @return PCAP generated packet header.
	 */
	public PcapPacketHeader getHeader();
	
	/**
	 * Original packet data as captured off of the wire by the PCAP library.
	 * 
	 * @return byte[] containing all of the byte captured. This can be less
	 * then actual packet on the wire depending how the capture was setup
	 * using the snapLen parameter.
	 */
	public byte[] getData();
}
