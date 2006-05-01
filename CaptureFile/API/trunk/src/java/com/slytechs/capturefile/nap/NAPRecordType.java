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
package com.slytechs.capturefile.nap;

import java.util.EnumSet;
import java.util.Set;

import com.slytechs.capturefile.RecordCapability;
import com.slytechs.capturefile.RecordType;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public enum NAPRecordType implements RecordType {
	BlockRecord(
			"Block record. Contains fileheader type information", 
			EnumSet.of(
					RecordCapability.FileMagicNumber)),
	NoOpRecord("Empty no-op record",
			EnumSet.of(
					RecordCapability.FilePaceholder)),
	PropertyRecord("Record containing user properties",
			EnumSet.of(
					RecordCapability.UserProperties, 
					RecordCapability.FileCompression,
					RecordCapability.FileEncryption,
					RecordCapability.FilePassword)),
	PacketRecord("Contains packet data, linktype and capture timestamp",
			EnumSet.of(
					RecordCapability.PacketBuffer,
					RecordCapability.PacketProtocol,
					RecordCapability.CaptureTimestampSeconds,
					RecordCapability.CaptureTimestampNanos)),
	PacketCounterRecord("Containing interface counters",
			EnumSet.of(
					RecordCapability.InterfaceCounterDrops,
					RecordCapability.InterfaceCounterInOctects,
					RecordCapability.InterfaceCounterInPackets,
					RecordCapability.InterfaceCounterOutOctects,
					RecordCapability.InterfaceCounterOutPackets)),
	PacketStatisticRecord("Contains analyzer statitics data",
			EnumSet.of(
					RecordCapability.AnalyzerStatistics)),
	;
	
	private final String description;
	private final Set<RecordCapability> capabilities;
	
	private NAPRecordType(String description, Set<RecordCapability> capabilities) {
		this.description = description;
		this.capabilities = capabilities;
	}
	
	public String getDescription() {
		return description;
	}
	
	public Set<RecordCapability> getCapabilities() {
		return capabilities;
	}
}
