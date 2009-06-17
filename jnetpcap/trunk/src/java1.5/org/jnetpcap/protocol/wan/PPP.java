/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
 * can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package org.jnetpcap.protocol.wan;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;

/**
 * Point to Point Protocol header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 5, dlt = PcapDLT.PPP)
public class PPP
    extends JHeader {

	public static final int ID = JProtocol.PPP_ID;
	
//	@Field(offset = 0, length = 8) 
//	public int flags() {
//		return getUByte(0);
//	}

	@Field(offset = 0, length = 8)
	public int address() {
		return getUByte(0);
	}

	@Field(offset = 8, length = 8)
	public int control() {
		return getUByte(1);
	}

	@Field(offset = 16, length = 16, format = "%x")
	public int protocol() {
		return getUShort(2);
	}

}
