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

import java.nio.ByteOrder;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.checksum.Checksum;

/**
 * IEEE 802.3 data link header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 14, dlt = PcapDLT.IEEE802)
public class IEEE802dot3
    extends JHeader {

	public static final int ID = JProtocol.IEEE_802DOT3_ID;

	@Field(offset = 0, length = 48, format = "#mac#")
	public byte[] destination() {
		return getByteArray(0, 6);
	}

	public byte[] destinationToByteArray(byte[] array) {
		return getByteArray(0, array);
	}

	public void destination(byte[] array) {
		setByteArray(0, array);
	}

	@Field(offset = 48, length = 48, format = "#mac#")
	public byte[] source() {
		return getByteArray(0 + 6, 6);
	}

	public void source(byte[] array) {
		setByteArray(0 + 6, array);
	}

	public byte[] sourceToByteArray(byte[] array) {
		return getByteArray(0 + 6, array);
	}

	@Field(offset = 96, length = 16, format = "%d")
	public int length() {
		return getUShort(0 + 12);
	}

	public void length(int len) {
		setUShort(0 + 12, len);
	}
	
	/**
	 * Checks if FCS is available for this Ethernet frame. FCS is typically
	 * stripped by the OS and not provided to Libpcap/jNetPcap on most platforms.
	 * 
	 * @return true if FCS is present, otherwise false
	 */
	@Dynamic(field = "checksum", value = Field.Property.CHECK)
	public boolean checksumCheck() {
		return getPostfixLength() >= 4;
	}

	/**
	 * Calculates the offset of the FCS field within the Ethernet frame.
	 * 
	 * @return offset, in bits, from the start of the packet buffer
	 */
	@Dynamic(Field.Property.OFFSET)
	public int checksumOffset() {
		return getPostfixOffset() * BYTE;
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String checksumDescription() {
		final long crc32 = calculateChecksum();
		if (checksum() == crc32) {
			return "correct";
		} else {
			return "incorrect: 0x" + Long.toHexString(crc32).toUpperCase();
		}
	}

	/**
	 * Retrieves the header's checksum.
	 * 
	 * @return header's stored checksum
	 */
	@Field(length = 4 * BYTE, format = "%x", display = "FCS")
	public long checksum() {
		final JPacket packet = getPacket();
		packet.order(ByteOrder.BIG_ENDIAN);
		return packet.getUInt(getPostfixOffset());
	}

	/**
	 * Calculates a checksum using protocol specification for a header. Checksums
	 * for partial headers or fragmented packets (unless the protocol allows it)
	 * are not calculated.
	 * 
	 * @return header's calculated checksum
	 */
	public long calculateChecksum() {
		if (getPostfixLength() < 4) {
			return 0L;
		}
		
		final JPacket packet = getPacket();
		return Checksum.crc32IEEE802(packet, 0, packet.size() - 4);
	}


}