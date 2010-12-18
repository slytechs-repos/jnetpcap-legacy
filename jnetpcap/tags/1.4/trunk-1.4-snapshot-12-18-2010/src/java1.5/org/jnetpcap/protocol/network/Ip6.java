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
package org.jnetpcap.protocol.network;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;

/**
 * IP version 6 header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 40)
public class Ip6
    extends JHeader {

	public static final int ID = JProtocol.IP6_ID;

	@Field(offset = 0, length = 4)
	public int version() {
		return getUByte(0) >> 4;
	}

	@Field(offset = 4, length = 8)
	public int trafficClass() {
		return getUShort(0) & 0x0FFF;
	}

	@Field(offset = 12, length = 20)
	public int flowLabel() {
		return getInt(0) & 0x000FFFFF; // We drop the sign bits anyway
	}

	@Field(offset = 32, length = 16)
	public int length() {
		return getUShort(4);
	}

	@Field(offset = 6 * 8, length = 8)
	@FlowKey(index = 1)
	public int next() {
		return getUByte(6);
	}

	@Field(offset = 7 * 8, length = 8)
	public int hopLimit() {
		return getUByte(7);
	}

	@Field(offset = 8 * 8, length = 128, format = "#ip6#")
	@FlowKey(index = 0)
	public byte[] source() {
		return getByteArray(8, 16);
	}

	public byte[] sourceToByteArray(byte[] address) {
		if (address.length != 16) {
			throw new IllegalArgumentException("address must be 16 byte long");
		}
		return getByteArray(8, address);
	}

	@Field(offset = 8 * 8, length = 128, format = "#ip6#")
	@FlowKey(index = 0)
	public byte[] destination() {
		return getByteArray(24, 16);
	}

	public byte[] destinationToByteArray(byte[] address) {
		if (address.length != 16) {
			throw new IllegalArgumentException("address must be 16 byte long");
		}
		return getByteArray(24, address);
	}

}