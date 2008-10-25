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
public class L2TP
    extends JHeader {
	
	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public final static int FLAG_L = 0x4000;
	
	public final static int FLAG_O = 0x0200;
	
	public final static int FLAG_P = 0x0100;
	
	public final static int FLAG_S = 0x0800;
	
	public final static int FLAG_T = 0x8000;
	
	public static final int ID = JProtocol.L2TP_ID;
	
	private int offId;
	private int offLength;
	private int offOffset;
	private int offSequence;
	
	/**
	 * @param id
	 */
	public L2TP() {
		super(ID);
		order(BYTE_ORDER);
	}
	
	public void decode() {
		int flags = flags();
		int o = 2;
		
		if (isSet(flags, FLAG_L)) {
			offLength = 2;
			o += 2;
		} else {
			offLength = 0;
		}
		
		offId = o;
		o += 4;
		
		if (isSet(flags, FLAG_S)) {
			offSequence = o;
			o += 4;
		} else {
			offSequence = 0;
		}
		
		if (isSet(flags, FLAG_O)) {
			offOffset = o;
			o += 4;
		} else {
			offOffset = 0;
		}
	}
	
	public int flags() {
		return getUShort(0);
	}
	
	private boolean isSet(int i, int m) {
		return (i & m) != 0;
	}
	
	public boolean hasLength() {
		return isSet(flags(), FLAG_L);
	}
	
	public boolean hasN() {
		return isSet(flags(), FLAG_S);
	}
	
	public boolean hasOffset() {
		return isSet(flags(), FLAG_O);
	}
	public int length() {
		return getUShort(offLength);
	}
	
	public int nr() {
		return getUShort(offSequence + 2);
	}
	
	public int ns() {
		return getUShort(offSequence);
	}
	
	public int offset() {
		return getUShort(offOffset);
	}

	public int pad() {
		return getUShort(offOffset + 2);
	}

	
	public int sessionId() {
		return getUShort(offId + 2);
	}
	
	public int tunnelId() {
		return getUShort(offId);
	}
}
