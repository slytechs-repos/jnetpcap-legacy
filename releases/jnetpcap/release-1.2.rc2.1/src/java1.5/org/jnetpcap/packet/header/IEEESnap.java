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
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldRuntime;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.FieldRuntime.FieldFunction;

/**
 * IEEE SNAP header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 5, nicname = "snap")
public class IEEESnap
    extends JHeader {

	public static final int ID = JProtocol.IEEE_SNAP_ID;
	
	@Field(offset = 0, length = 24, format = "%x")
	public long oui() {
		return getUInt(0) & 0x00FFFFFF;
	}

	@FieldRuntime(FieldFunction.DESCRIPTION)
	public String pidDescription() {
		return Ethernet.EthernetType.toString(pid());
	}
	
	@Field(offset = 24, length = 16, format = "%x")
	public int pid() {
		return getUShort(3);
	}
}