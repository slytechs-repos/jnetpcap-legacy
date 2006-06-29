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

import com.slytechs.capture.file.capabilities.Capability;
import com.slytechs.capture.file.type.CaptureFileHandler;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface CaptureFileType {

	public String getDescription();
	
	public Set<Capability> getSupportedCapabilities();

	/**
	 * @return
	 */
	public CaptureFileHandler getDefaultHandler();
	
	/**
	 * <P>Helps deterimine if this file type is easily indexible or
	 * if this is a major understask. Use this method to determine
	 * the best algorithm to use with any specific file type. PCAP and
	 * SNOOP files for example, are not easily indexible and can only be
	 * done so at extreme resource expense, while other formats such as NAP are
	 * easily indexible and can easily be indexed.</P>
	 * 
	 * <P>Note that in programming any type of file can be turned into an index file,
	 * but at great CPU, time and memory expense. You can use this generic method to
	 * determine if this is a worth while excersize of another approach or algorithm
	 * should be used.</P>
	 * 
	 * @return
	 *   true if file is easily indexible otherwise false. 
	 */
	public boolean isIndexable();
}
