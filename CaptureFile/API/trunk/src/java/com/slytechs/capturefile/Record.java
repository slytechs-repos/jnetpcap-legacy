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
package com.slytechs.capturefile;

import com.slytechs.utils.net.ByteEncoding;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface Record {
	
	/**
	 * Returns if this record contains packet data. Not all
	 * records contain packet data, they may contain META information
	 * that is not specifically packet data, but in support of the packet.
	 * 
	 * @return
	 *   true if this record is of type PacketRecord otherwise false.
	 */
	public boolean isPacketRecord();
	
	/**
	 * <P>Returns an instance of PacketRecord which contains packet data.
	 * You must use isPacketRecord() before calling this method
	 * to ensure that this record is of type PacketRecord. If you do
	 * not call isPacketRecord() first, prior to this call, an
	 * IllegalStateException will be thrown.</P>
	 * 
	 * <P>Further more, you may not typecast this Record object into
	 * PacketRecord class even if you think it is of this type.</P>
	 * 
	 * @return
	 *   Returns an instance of PacketRecord. This method never returns null.
	 */
	public PacketRecord getPacketRecord();
	
	/**
	 * Returns the file position of the start of this record.
	 * 
	 * @return
	 *   start of this record
	 */
	public long getFilePosition();
	
	/**
	 * Returns the length of this record in bytes. The record
	 * length includes the record header, from the start of the record,
	 * and contains all the data within the record. 
	 * The formula GetFilePosition() + getLength() points at the first byte
	 * of the next record.
	 * 
	 * @return
	 */
	public int getLength();
	
	/**
	 * Returns the type of this record.
	 * 
	 * @return
	 *   Type of this record.
	 */
	public RecordType getType();
	
	/**
	 * Returns the byte ordering (big or little endian). Values
	 * retrieved from any of the getter methods convert the
	 * values into BigEndian or Network byte order for processing.
	 * The encoding type returned here, is the byte order as
	 * written in the physical file.
	 * 
	 * @return
	 *   the byte order of this record
	 */
	public ByteEncoding getByteEncoding();
}
