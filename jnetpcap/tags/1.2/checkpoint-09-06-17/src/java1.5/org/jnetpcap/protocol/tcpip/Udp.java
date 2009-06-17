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
package org.jnetpcap.protocol.tcpip;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.checksum.Checksum;

/**
 * Udp/Ip header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 8)
public class Udp
    extends JHeader {

	public static final int ID = JProtocol.UDP_ID;

	@Field(offset = 0, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int source() {
		return getUShort(0);
	}

	@Field(offset = 2 * 8, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int destination() {
		return getUShort(2);
	}

	@Field(offset = 4 * 8, length = 16)
	public int length() {
		return getUShort(4);
	}
	
	@Dynamic(Field.Property.DESCRIPTION)
	public String checksumDescription() {
		
		if (isFragmented()) {
			return "supressed for fragments";
		}
		
		if (isPayloadTruncated()) {
			return "supressed for truncated packets";
		}
		
		final int crc16 = calculateChecksum();
		if (checksum() == crc16) {
			return "correct";
		} else {
			return "incorrect: 0x" + Integer.toHexString(crc16).toUpperCase();
		}
	}

	@Field(offset = 6 * 8, length = 16, format = "%x")
	public int checksum() {
		return getUShort(6);
	}

	public int calculateChecksum() {

		if (getIndex() == -1) {
			throw new IllegalStateException("Oops index not set");
		}

		final int ipOffset = getPreviousHeaderOffset();

		return Checksum.pseudoUdp(packet, ipOffset, this.getOffset());
	}

}
