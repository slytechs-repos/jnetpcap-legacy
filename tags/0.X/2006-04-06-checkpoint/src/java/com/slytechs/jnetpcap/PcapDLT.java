/**
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
package com.slytechs.jnetpcap;

/**
 * PCAP library DLT values (Data Link Type) values. This
 * interface provides access to the mapping between String and
 * numerical values used by PCAP. PCAP actually supplies its
 * own methods for accessing the name and description of each
 * DLT.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface PcapDLT {
	
	public enum DLT implements PcapDLT {
		NULL_BSD,
		EN10MB,
		IEEE802,
		ARCNET,
		SLIP,
		PPP,
		FDDI,
		ATM_RFC1483,
		RAW,
		PPP_SERIAL,
		PPP_ETHER,
		C_HDLC,
		IEEE802_11,
		FRELAY,
		LOOP,
		LINUX_SLL,
		LTALK,
		PFLOG,
		PRISM_HEADER,
		IP_OVER_FC,
		SUNATM,
		IEEE802_11_RADIO,
		ARCNET_LINUX,
		LINUX_IRDA
		;
		
	}

	/**
	 * Returns PCAP library supplied description 
	 * for the given DLT.
	 * 
	 * @return
	 *   DLT description.
	 */
	public String getDescription();
	
	
	/**
	 * Returns PCAP library supplied name for the
	 * DLT.
	 * 
	 * @return
	 *   DLT name.
	 */
	public String getName();
	
	/**
	 * Maps object to an actual PCAP DLT integer value.
	 * 
	 * @return
	 *   Integer value used by PCAP library in assigning
	 *   DLTs to packets.
	 */
	public int value();
}
