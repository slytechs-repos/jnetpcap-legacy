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
package org.jnetpcap.protocol.vpn;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.JProtocol;

/**
 * Layer 2 Tunneling Protocol header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
public class L2TP
    extends JHeader {

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		int flags = buffer.getUShort(0);
		int len = 6;
		if ((flags & FLAG_L) != 0) {
			len += 2;
		}

		if ((flags & FLAG_S) != 0) {
			len += 4;
		}

		if ((flags & FLAG_O) != 0) {
			len += 4;
		}

		return len;
	}

	public final static int FLAG_L = 0x4000;

	public final static int FLAG_O = 0x0200;

	public final static int FLAG_P = 0x0100;

	public final static int FLAG_S = 0x0800;

	public final static int FLAG_T = 0x8000;

	public static final int ID = JProtocol.L2TP_ID;

	public final static int MASK_VERSION = 0x000E;
	
	public final static int MASK_FLAGS = 0xFFF1;

	private int offId;

	private int offLength;

	private int offOffset;

	private int offSequence;

	public void decodeHeader() {

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

	@Field(offset = 0, length = 12, format = "%x")
	public int flags() {
		return getUShort(0) & MASK_FLAGS;
	}

	@Dynamic(Field.Property.CHECK)
	public boolean hasLength() {
		return isSet(flags(), FLAG_L);
	}

	@Dynamic(Field.Property.CHECK)
	public boolean hasN() {
		return isSet(flags(), FLAG_S);
	}

	@Dynamic(Field.Property.CHECK)
	public boolean hasOffset() {
		return isSet(flags(), FLAG_O);
	}

	private boolean isSet(int i, int m) {
		return (i & m) != 0;
	}
	
	
	@Dynamic(Field.Property.OFFSET)
	public int lengthOffset() {
		return offLength * 8;
	}

	@Field(length = 16)
	public int length() {
		return getUShort(offLength);
	}
	
	@Dynamic(Field.Property.OFFSET)
	public int nrOffset() {
		return (offSequence + 2) * 8;
	}

	@Field(length = 16)
	public int nr() {
		return getUShort(offSequence + 2);
	}

	@Dynamic(Field.Property.OFFSET)
	public int nsOffset() {
		return offSequence * 8;
	}
	
	@Field(length = 16)
	public int ns() {
		return getUShort(offSequence);
	}

	@Dynamic(Field.Property.OFFSET)
	public int offsetOffset() {
		return offOffset * 8;
	}
	
	@Field(length = 16)
	public int offset() {
		return getUShort(offOffset);
	}

	@Dynamic(Field.Property.OFFSET)
	public int padOffset() {
		return (offLength + 2) * 8;
	}
	
	@Field(length = 16)
	public int pad() {
		return getUShort(offOffset + 2);
	}

	@Dynamic(Field.Property.OFFSET)
	public int sessionIdOffset() {
		return (offId * 2) * 8;
	}
	
	@Field(length = 16)
	public int sessionId() {
		return getUShort(offId + 2);
	}

	@Dynamic(Field.Property.OFFSET)
	public int tunnelIdOffset() {
		return offId * 8;
	}
	
	@Field(length = 16)
	public int tunnelId() {
		return getUShort(offId);
	}

	@Field(offset = 13, length = 3)
	public int version() {
		return getUShort(0) & MASK_VERSION;
	}
}
