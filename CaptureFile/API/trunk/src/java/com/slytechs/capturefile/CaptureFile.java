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

import java.io.File;
import java.nio.ByteOrder;

import com.slytechs.utils.number.Version;

/**
 * Main interface to an open capture file. Use the factory
 * method open(File) to get an instance of this interface.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class CaptureFile implements Iterable<Record>{
	
	public static CaptureFile open(File file) {
		return null;
	}
	
	/**
	 * Returns file type of the currently open file.
	 * 
	 * @return
	 *   file type of the open capture file
	 */
	public abstract CaptureFileType getType();
	
	public abstract ByteOrder getByteOrder();
	
	/**
	 * Returns the first file version found. There may be
	 * multiple blocks within the file at different versions.
	 *  
	 * @return
	 *   version of the file
	 */
	public abstract Version getVersion();

}
