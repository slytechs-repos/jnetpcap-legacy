/**
 * Copyright (C) 2008 Sly Technologies, Inc.
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
package org.jnetpcap.packet.header;

import java.nio.ByteOrder;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JProtocol;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class Tcp
    extends JHeader {
	
	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public static final int ID = JProtocol.TCP_ID;
	
	public static final int LENGTH = 20;

	/**
	 * @param id
	 */
	public Tcp() {
		super(ID, "tcp", "tcp");
		order(BYTE_ORDER);
	}
	
	public int source() {
		return getUShort(0);
	}
	
	public int destination() {
		return getUShort(2);
	}
	
	public long seq() {
		return getUInt(4);
	}
	
	public long ack() {
		return getUInt(8);
	}
	
	public int offset() {
		return getUByte(12) & 0xF0;
	}
	
	public int reserved() {
		return getUShort(12) & 0x0E00;
	}
	
	public int ecn() {
		return getUShort(12) & 0x01C0;
	}
	
	public int control() {
		return getUShort(12) & 0x003F;
	}

	public int window() {
		return getUShort(14);
	}
	
	public int checksum() {
		return getUShort(16);
	}
	
	public int urgent() {
		return getUShort(18);
	}

}
