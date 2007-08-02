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
package com.slytechs.capture.file.type.pcap;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.EnumSet;
import java.util.Set;

import com.slytechs.capture.file.RecordType;
import com.slytechs.capture.file.capabilities.Capability;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public enum PCAPRecordType implements RecordType{
	FileHeaderRecord("File header containing global file information",
			"",
			EnumSet.of(
					Capability.EntityTimezone,
					Capability.FileMagicNumber,
					Capability.FileVersion,
					Capability.EntityTimezone,
					Capability.PacketProtocol)),
	PacketRecord("Record containing packet buffer and capture timestamp",
			"",
			EnumSet.of(
					Capability.PacketBuffer,
					Capability.CaptureTimestampSeconds,
					Capability.CaptureTimestampMicros)),
	;
	
	private final String description;
	private final Set<Capability> capabilities;
	private final URI spec;

	private PCAPRecordType(String description, String spec, EnumSet<Capability> capabilities) {
		this.description = description;
		try {
			this.spec = new URI(spec);
		} catch (URISyntaxException e) {
			throw new IllegalStateException("Internal error: this should not happen", e);
		}
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
	public Set<Capability> getCapabilities() {
		return capabilities;
	}

	/**
	 * @return Returns the spec.
	 */
	public URI getSpec() {
		return spec;
	}

}
