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
package org.jnetpcap.protocol.lan;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.JProtocol;

/**
 * IEEE LLC2 header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(nicname = "llc")
public class IEEE802dot2
    extends JHeader {

	public static final int ID = JProtocol.IEEE_802DOT2_ID;

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		return ((buffer.getUShort(offset + 2) & 0x3) == 0x3) ? 4 : 5;
	}

	@Field(offset = 0, format = "%x")
	public int control() {
		/*
		 * This field is either 1 or 2 bytes in length depending on the control bit.
		 */
		int c = getUByte(2);
		if ((c & 0x3) == 0x3) {
			return c;
		} else {
			return getUShort(2);
		}
	}

	@Dynamic(Field.Property.LENGTH)
	public int controlLength() {
		return ((super.getUByte(2) & 0x3) == 0x3) ? 1 * 8 : 2 * 8;
	}

	@Field(offset = 0, length = 8, format = "%x")
	public int dsap() {
		return getUByte(0);
	}

	@Field(offset = 8, length = 8, format = "%x")
	public int ssap() {
		return getUByte(1);
	}
}