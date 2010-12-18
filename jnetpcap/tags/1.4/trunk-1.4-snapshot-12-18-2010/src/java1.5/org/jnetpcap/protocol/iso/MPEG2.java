/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.protocol.iso;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 188, suite = ProtocolSuite.ISO, description = "ISO/IEC 13818-1")
public class MPEG2
    extends
    JHeader {

	private int length = 4;
	private int offset = 4;

	@Field(offset = 0, length = 4 * BYTE, format = "%x")
	public long header() {
		return getUInt(0);
	}
	
	@Dynamic(Field.Property.DESCRIPTION)
	public String header_syncByteDescription() {
		if (header_syncByte() == 0x47) {
			return String.format("correct (0x%X)", header_syncByte());
		} else {
			return "invalid";
		}
	}

	@Field(parent = "header", offset = 24, length = 8, display = "Sync Byte")
	public long header_syncByte() {
		return (header() >> 24) & 0xFF;
	}

	@Field(parent = "header", offset = 23, length = 1, display = "Transport Error Indicator")
	public long header_TransportErrorIndicator() {
		return (header() >> 23) & 0x1;
	}

	@Field(parent = "header", offset = 22, length = 1, display = "Payload Unit Start Indicator")
	public long header_PayloadUnitStart() {
		return (header() >> 22) & 0x1;
	}

	@Field(parent = "header", offset = 21, length = 1, display = "Transport Priority")
	public long header_TransportPriority() {
		return (header() >> 21) & 0x1;
	}
	
	@Dynamic(Field.Property.DESCRIPTION)
	public String header_PIDDescription() {
			return String.format("(0x%X)", header_PID());
	}


	@Field(parent = "header", offset = 8, length = 13, display = "PID")
	public long header_PID() {
		return (header() >> 8) & 0x12FF;
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String header_TransportScramblingControlDescription() {
		if (header_TransportScramblingControl() == 0) {
			return String.format("not scramboled (0x%X)", header_TransportScramblingControl());
		} else {
			return String.format("scramboled (0x%X)", header_TransportScramblingControl());
		}
	}
	
	@Field(parent = "header", offset = 6, length = 2, display = "Transport Scrambling Control")
	public long header_TransportScramblingControl() {
		return (header() >> 6) & 0x03;
	}
	
	@Dynamic(Field.Property.DESCRIPTION)
	public String header_AdaptionFieldControlDescription() {
		if (header_AdaptionFieldControl() == 0x1) {
			return String.format("payload only (0x%X)", header_AdaptionFieldControl());
		} else {
			return String.format("adaptation and payload (0x%X)", header_AdaptionFieldControl());
		}
	}
	

	@Field(parent = "header", offset = 4, length = 2, display = "Adaption Field Control")
	public long header_AdaptionFieldControl() {
		return (header() >> 4) & 0x03;
	}
	
	@Dynamic(Field.Property.DESCRIPTION)
	public String header_ContinuityCounterDescription() {
			return String.format("%d", header_ContinuityCounter());
	}


	@Field(parent = "header", offset = 0, length = 4, display = "Continuity Counter")
	public long header_ContinuityCounter() {
		return (header() >> 0) & 0x0F;
	}

	@Dynamic(Field.Property.LENGTH)
	public int payloadLength() {
		return this.length * BYTE;
	}
	
	@Dynamic(Field.Property.OFFSET)
	public int payloadOffset() {
		return this.offset * BYTE;
	}

	@Field(format = "#hexdump#")
	public byte[] payload() {
		return getByteArray(offset, length);
	}
	
	@Dynamic(field = "adaptationFieldLength", value = Field.Property.CHECK)
	public boolean adaptationFieldLengthCheck() {
		return adaptationFieldCheck();
	}
		
	@Field(offset = 4 * BYTE, length = 1 * BYTE, display = "field length")
	public int adaptationFieldLength() {
		return getUByte(4);
	}


	@Dynamic(field = "adaptationField", value = Field.Property.CHECK)
	public boolean adaptationFieldCheck() {
		return (header_AdaptionFieldControl() & 0x2) == 0x2;
	}

	@Field(offset = 5 * BYTE, length = 1 * BYTE)
	public int adaptationField() {
		return getUByte(5);
	}

	@Override
	protected void decodeHeader() {
		final int remaining = getPacket().size() - getOffset();
		length = (remaining >= 188) ? 188 - 4 : remaining;
		
		if (adaptationFieldCheck()) {
			length -= (adaptationFieldLength() + 1);
			offset += (adaptationFieldLength() + 1);
		}
	}

}
