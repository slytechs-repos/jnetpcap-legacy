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

/**
 * IP version 4 network protocol header.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Ip4
    extends JHeader {

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public static final int ID = JProtocol.IP4_ID;

	public Ip4() {
		super(ID);
		super.order(BYTE_ORDER);
	}

	public int version() {
		return getUByte(0) >> 4;
	}

	public int hlen() {
		return getUByte(0) & 0x0F;
	}

	public int tos() {
		return getUByte(1);
	}

	public int length() {
		return getUShort(2);
	}

	public int id() {
		return getUShort(4);
	}

	public int flags() {
		return getUByte(6) >> 5;
	}

	public int offset() {
		return getUShort(6) & 0x1FFF;
	}

	public int ttl() {
		return getUByte(8);
	}

	public int type() {
		return getUByte(9);
	}

	public int checksum() {
		return getUShort(10);
	}

	public byte[] source() {
		return getByteArray(12, 4);
	}

	public byte[] sourceToByteArray(byte[] address) {
		if (address.length != 4) {
			throw new IllegalArgumentException("address must be 4 byte long");
		}
		return getByteArray(12, address);
	}

	public byte[] destination() {
		return getByteArray(16, 4);
	}

	public byte[] destinationToByteArray(byte[] address) {
		if (address.length != 4) {
			throw new IllegalArgumentException("address must be 4 byte long");
		}
		return getByteArray(16, address);
	}
}