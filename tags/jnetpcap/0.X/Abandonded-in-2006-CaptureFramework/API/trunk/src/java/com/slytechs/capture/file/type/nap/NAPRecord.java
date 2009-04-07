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
package com.slytechs.capture.file.type.nap;

import java.io.IOException;
import java.nio.ByteBuffer;

import com.slytechs.capture.file.ValidationException;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface NAPRecord {


	public static final int HDR_RECORD_LENGTH = 4;
	
	public static final int HDR_TYPE = 0;
	/**
	 * Record's header length in octets
	 */
	public static final int RECORD_HEADER_LENGTH = 24;
	
	public void flush() throws IOException;
	
	public ByteBuffer getContentBuffer();
	
	public NAPModel getFile();
	
	public ByteBuffer getHeaderBuffer();
	public long getHeaderLength();
	
	public long getLastModified();
	public ByteBuffer getRecordBuffer() throws IOException;
	public void clearRecordBuffer();
	public long getRecordLength();
	public NAPRecordType getRecordType();
	
	/**
	 * @return
	 */
	public long getStart();
	public boolean isModified();
	

	public boolean isWritten();

	public void setLastModified();


	public void setLastModified(long lastModified);


	public void setModified(boolean state);
	
	public void setRecordType(NAPRecordType type);
			
	/**
	 * @param l
	 */
	public void setStart(long l);	
	public void setWritten(boolean state);

	public void validateRecord() throws ValidationException;
	
	/**
	 * @throws IOException 
	 * 
	 */
	public void write() throws IOException;
}
