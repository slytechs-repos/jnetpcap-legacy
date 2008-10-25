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

import java.nio.ByteOrder;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JProtocol;

public class IEEE802dot2
    extends JHeader {

	public static final int ID = JProtocol.IEEE_802DOT2_ID;

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public IEEE802dot2() {
		super(ID);
		order(BYTE_ORDER);
	}

	public int dsap() {
		return getUByte(0);
	}

	public int ssap() {
		return getUByte(1);
	}

	public int control() {
		/*
		 * This field is either 1 or 2 bytes in length depending on the control bit.
		 */
		int c = getUShort(2);
		if ((c & 0x3) == 0x3) {
			return c & 0x00FF;
		} else {
			return c;
		}
	}
}