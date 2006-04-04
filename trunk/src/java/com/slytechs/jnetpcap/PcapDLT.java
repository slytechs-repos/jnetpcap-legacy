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
package com.slytechs.jnetpcap;

/**
 * PCAP library DLT values (Data Link Type) values. This
 * interface provides access to the mapping between String and
 * numerical values used by PCAP. PCAP actually supplies its
 * own methods for accessing the name and description of each
 * DLT.
 * 
 * @author Mark Bednarczyk
 */
public abstract class PcapDLT {

	/**
	 * Maps a DLT name to a DLT value.
	 * 
	 * @param name 
	 *   DLT name to be mapped.
	 * @return
	 *   DLT object or null if not found.
	 */
	public static PcapDLT valueOf(String name) {
		return null;
	}
	
	/**
	 * Returns PCAP library supplied description 
	 * for the given DLT.
	 * 
	 * @return
	 *   DLT description.
	 */
	public String getDescription() {
		return "";
	}
	
	
	/**
	 * Returns PCAP library supplied name for the
	 * DLT.
	 * 
	 * @return
	 *   DLT name.
	 */
	public String getName() {
		return "";
	}
	
	/**
	 * Maps object to an actual PCAP DLT integer value.
	 * 
	 * @return
	 *   Integer value used by PCAP library in assigning
	 *   DLTs to packets.
	 */
	public int value() {
		return 0;
	}
}
