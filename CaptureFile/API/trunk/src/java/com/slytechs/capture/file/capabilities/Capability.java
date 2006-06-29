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
package com.slytechs.capture.file.capabilities;


/**
 * Enum constants that describe certain capabilities and thus information
 * a particular type of record may contain. Some implementations may contain
 * additional capabilities not defined by these constants.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public enum Capability {
	
	/**
	 * Record contains a packet buffer with packet data.
	 */
	PacketBuffer,
	
	/**
	 * Record contains information about PacketProtocol, the
	 * first protocol, usually linktype, within the PacketBuffer.
	 */
	PacketProtocol,
	
	/**
	 * Record contains capture a timestamps in seconds 
	 */
	CaptureTimestampSeconds,
	
	/**
	 * Record contains capture a timestamps of fraction of a seconds in micros. 
	 * Legal value is between 0 and 999,999 inclusive
	 */
	CaptureTimestampMicros,
	
	/**
	 * Record contains capture a timestamps of fraction of a seconds in nanos.
	 * Legal value is between 0 and 999,999,999 inclusive
	 */ 
	CaptureTimestampNanos,
	
	/**
	 * Timezone information about the capture entity or capture system is known.
	 * For remote capture systems, the timezone may be different.
	 */
	EntityTimezone,
	
	/**
	 * Record contains interface packet drops counter
	 */
	InterfaceCounterDrops,
	
	/**
	 * Record contains interface ingres packet counter
	 */
	InterfaceCounterInPackets,
	
	/**
	 * Record contains interface ingres octets counters. Bytes received.
	 */
	InterfaceCounterInOctects,
	
	/**
	 * Record contains interface egress packet counter
	 */
	InterfaceCounterOutPackets,
	
	/**
	 * Record contains interface egress octet counter. Bytes sent.
	 */
	InterfaceCounterOutOctects,
	
	/**
	 * Record contains a password to protect the file
	 */
	FilePassword,
	
	/**
	 * Record contains a compression algorithm information to compress the files content
	 */
	FileCompression,
	
	/**
	 * Record contains information about file encryption algorithm.
	 */
	FileEncryption,
	
	/**
	 * Record contains user properties in AV pair format "property = value"
	 */
	UserProperties,
	
	/**
	 * Record contains version information about the file or block within the file.
	 */
	FileVersion,
	
	/**
	 * Record contains a MAGIC number specific for this file type.
	 */
	FileMagicNumber,
	
	/**
	 * Record contains analyzer produced statistics
	 */
	AnalyzerStatistics,
	
	/**
	 * Block contents can be mutated in place without file copies (size and content can change)
	 */
	InPlaceMutableBlock, FilePaceholder,
	
	;
	
	public Class getCapabilityInterface() {
		return InterfaceCounters.class;
	}

}
