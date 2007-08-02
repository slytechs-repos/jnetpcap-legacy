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
package com.slytechs.capture.file.nap;

import java.net.URI;
import java.net.URISyntaxException;

import com.slytechs.capture.file.RecordType;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public enum NAPRecordType implements RecordType {
	BlockRecord(0x1, 
			"Block record. Contains file header type information", 
			"file:///E:/Documents%20and%20Settings/markbe/My%20Documents/jNetPCAP/docs/draft-slytechs-network-nap-00.htm#_Toc134508389"),

	NoOpRecord(0xF, "Empty no-op record",
			"file:///E:/Documents%20and%20Settings/markbe/My%20Documents/jNetPCAP/docs/draft-slytechs-network-nap-00.htm#_Toc134508391"),
			
	MetaRecord(0x2, "Contains additional meta information about the block or record",
			"file:///E:/Documents%20and%20Settings/markbe/My%20Documents/jNetPCAP/docs/draft-slytechs-network-nap-00.htm#_Toc134508393"),
			
	PacketRecord(0x0, "Contains packet data, linktype and capture timestamp",
			"file:///E:/Documents%20and%20Settings/markbe/My%20Documents/jNetPCAP/docs/draft-slytechs-network-nap-00.htm#_Toc134508390"),
			
	Vendor(0x3, "Vendor specific extension record",
			"file:///E:/Documents%20and%20Settings/markbe/My%20Documents/jNetPCAP/docs/draft-slytechs-network-nap-00.htm#_Toc134508392"),
	;
	
	private final String description;
	private final URI spec;
	private final int type;
	
	private NAPRecordType(int type, String description, String spec) {
		this.type = type;
		this.description = description;
		try {
			this.spec = new URI(spec);
		} catch (URISyntaxException e) {
			throw new IllegalStateException("Internal error: this shouldn't happen", e);
		}

	}
	
	public String getDescription() {
		return description;
	}

	/**
	 * @return Returns the spec.
	 */
	public URI getSpec() {
		return spec;
	}

	/**
	 * @return Returns the type.
	 */
	public int getType() {
		return type;
	}
	
	public static NAPRecordType valueOf(int type) {
		for (NAPRecordType t: values()) {
			if (t.type == type) {
				return t;
			}
		}
		
		return null;
	}
}
