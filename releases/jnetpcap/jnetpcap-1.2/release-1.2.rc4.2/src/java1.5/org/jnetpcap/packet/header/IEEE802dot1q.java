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
package org.jnetpcap.packet.header;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;

/**
 * IEEE Vlan header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 4, nicname = "vlan")
public class IEEE802dot1q
    extends JHeader {

	public static final int ID = JProtocol.IEEE_802DOT1Q_ID;


	@Field(offset = 0, length = 3, format = "%d")
	public int priority() {
		return (getUByte(0) & 0xE0) >> 5;
	}

	@Field(offset = 3, length = 1, format = "%x")
	public int cfi() {
		return (getUByte(0) & 0x10) >> 4;
	}

	@Field(offset = 4, length = 12, format = "%x")
	public int id() {
		return getUShort(0) & 0x0FFF;
	}
	
	@Dynamic(Field.Property.DESCRIPTION)
	public String typeDescription() {
		return Ethernet.EthernetType.toString(type());
	}

	@Field(offset = 16, length = 16, format = "%x")
	public int type() {
		return getUShort(2);
	}
}