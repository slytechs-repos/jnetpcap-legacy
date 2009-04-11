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

import java.io.IOException;
import java.util.Set;

import com.slytechs.capture.file.capabilities.Capability;
import com.slytechs.capture.file.capabilities.UnsupportCapabilityException;
import com.slytechs.utils.net.ByteEncoding;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface Record {

	/**
	 * Returns the file position of the start of this record.
	 * 
	 * @return
	 *   start of this record
	 */
	public long getFilePosition();
	
	public void setFilePosition(long position);
	
	/**
	 * Returns the length of this record in bytes. The record
	 * length includes the record header, from the start of the record,
	 * and contains all the data within the record. 
	 * The formula GetFilePosition() + getLength() points at the first byte
	 * of the next record.
	 * 
	 * @return
	 */
	public long getLength();
	
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
	
	/**
	 * Sets the byte encoding of this record. Care must be taken to set the
	 * byte enconding of supported type for each record. Otherwise the method
	 * will throw IllegalStateException.
	 * 
	 * @param encoding
	 *   encoding to use for this record
	 *   
	 * @throws IllegalStateException
	 *   if encoding format is not supported by this record type
	 */
	public void setByteEncoding(ByteEncoding encoding);
	
	public <C> C getCapability(Capability capabilty) throws UnsupportCapabilityException;
	
	public Set<Capability> getCapabilities();


	public void read() throws IOException;
	public void write() throws IOException;

	public void readHeader() throws IOException;
	public void writeHeader() throws IOException;

	public Record getParent();
}
