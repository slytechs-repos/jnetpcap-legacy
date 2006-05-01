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
package com.slytechs.capturefile.pcap;

import java.util.EnumSet;
import java.util.Set;

import com.slytechs.capturefile.RecordCapability;
import com.slytechs.capturefile.RecordType;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public enum PCAPRecordType implements RecordType{
	FileHeaderRecord("File header containing global file information",
			EnumSet.of(
					RecordCapability.EntityTimezone,
					RecordCapability.FileMagicNumber,
					RecordCapability.FileVersion,
					RecordCapability.EntityTimezone,
					RecordCapability.PacketProtocol)),
	PacketRecord("Record containing packet buffer and capture timestamp",
			EnumSet.of(
					RecordCapability.PacketBuffer,
					RecordCapability.CaptureTimestampSeconds,
					RecordCapability.CaptureTimestampMicros)),
	;
	
	private final String description;
	private final Set<RecordCapability> capabilities;

	private PCAPRecordType(String description, EnumSet<RecordCapability> capabilities) {
		this.description = description;
		this.capabilities = capabilities;
	}

	/**
	 * @return Returns the description.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * @return Returns the capabilities.
	 */
	public Set<RecordCapability> getCapabilities() {
		return capabilities;
	}

}
