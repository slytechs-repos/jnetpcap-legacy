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

import java.nio.ByteBuffer;

import com.slytechs.capture.file.capabilities.CaptureTimestamp;
import com.slytechs.utils.io.BitBuffer;

/**
 * A special interface that provides access to captured packets data including 
 * meta information that may reside in other places within the file. That is 
 * this interface does not neccessarily represent a 1-to-1 relationship with
 * any record contained within the capture file. For example, in the simplest 
 * case the interface returns the DLT type of the first header within the 
 * packet record content, while this information may be actually extracted from the
 * file header (BlockRecord.) Or it may be provided from the packet record itself.
 * In more advanced example packet counters may reside in some other meta records
 * within the file associated with this particular packet. This is all file type
 * dependent and abstracted by this high level interface.
 *  
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface CapturePacket extends Record, CaptureTimestamp {

	public int getProtocolNumber();
	public String getProtocolName();
	
	public byte[] toByteArray();
	
	public ByteBuffer toByteBuffer();
	
	public BitBuffer toBitBuffer();
	
	public void setPacketData(byte[] data);
	public void setPacketData(ByteBuffer buffer);
	public void setPacketData(BitBuffer buffer);
	
	public long getPacketDataPosition();
	
	public int getPacketDataLength();
}
