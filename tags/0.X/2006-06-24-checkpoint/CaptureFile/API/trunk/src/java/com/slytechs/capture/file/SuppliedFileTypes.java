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
package com.slytechs.capture.file;

import java.util.Set;

/**
 * Defines constants for all the currently supported capture file types.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public enum SuppliedFileTypes implements CaptureFileType {
	NAP("Network Capture file format sponsored by Sly Technologies, Inc."),
	PCAP("Packet Capture file format from Tcpdump.org"),
	Snoop("Sun's capture file format"),
	Snort("SNORT.org file capture format")
	;
	
	private final String description;

	private SuppliedFileTypes(String description) {
		this.description = description;
		
	}

	/**
	 * Returns a short description of the file format. 
	 * 
	 * @return Returns the description.
	 */
	public String getDescription() {
		return description;
	}
	
	public Set<Capability> getSupportedCapabilities() {
		return null;
	}
	
	public CaptureFileHandler getDefaultHandler() {
		return null;
	}

}
