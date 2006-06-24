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

import java.net.URI;

/**
 * Interface that allows retrieval of type information about
 * each impelementation specific record type.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface RecordType {
	
	/**
	 * Short description of this type of record. The
	 * description is implementation specific.
	 * 
	 * @return
	 *   short description
	 */
	public String getDescription();
	
	/**
	 * Returns the URI to formal specification for this record type.
	 * Some records may be vendor specific and each vendor supply a
	 * valid URI to the formal specification for this type of record.
	 * 
	 * @return
	 *   URI which contains the formal specification of this record type
	 */
	public URI getSpec();

}
