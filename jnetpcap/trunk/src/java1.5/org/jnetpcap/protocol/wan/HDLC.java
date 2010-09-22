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
package org.jnetpcap.protocol.wan;

import java.nio.ByteOrder;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.lan.IEEE802dot1d;
import org.jnetpcap.protocol.lan.Ethernet.EthernetType;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.util.checksum.Checksum;

/**
 * High-Level Data Link Control (HDLC) is a bit-oriented synchronous data link
 * layer protocol developed by the International Organization for
 * Standardization (ISO). The original ISO standards for HDLC are:
 * <ul>
 * <li> ISO 3309 - Frame Structure
 * <li> ISO 4335 - Elements of Procedure
 * <li> ISO 6159 - Unbalanced Classes of Procedure
 * <li> ISO 6256 - Balanced Classes of Procedure
 * </ul>
 * <p>
 * The current standard for HDLC is ISO 13239, which replaces all of those
 * standards.
 * </p>
 * <p>
 * HDLC provides both connection-oriented and connectionless service.
 * </p>
 * <p>
 * HDLC can be used for point to multipoint connections, but is now used almost
 * exclusively to connect one device to another, using what is known as
 * Asynchronous Balanced Mode (ABM). The original master-slave modes Normal
 * Response Mode (NRM) and Asynchronous Response Mode (ARM) are rarely used.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 4, description = "High-Level Datalink Control", dlt = PcapDLT.C_HDLC)
public class HDLC
    extends
    JHeader {

	/**
	 * Change the byte ordering. HDLC is little-endian.
	 */
	public HDLC() {
		super.order(ByteOrder.LITTLE_ENDIAN);
	}

	/**
	 * Sets a new binding between Ip4 and HDLC headers
	 * 
	 * @param packet
	 *          the packet to perform the check on
	 * @param hdlc
	 *          HDLC fame to be bound to
	 * @return true if the next header in HDLC frame is Ip4
	 */
	@Bind(from = Ip4.class, to = HDLC.class)
	public static boolean bindIp4toHDLC(JPacket packet, HDLC hdlc) {
		return hdlc.code() == 0x800;
	}

	/**
	 * Sets a new binding between STP and HDLC headers.
	 * 
	 * @param packet
	 *          the packet to perform the check on
	 * @param hdlc
	 *          HDLC frame to be bound to
	 * @return true if the next header in HDLC frame is STP
	 */
	@Bind(from = IEEE802dot1d.class, to = HDLC.class)
	public static boolean bindStpToHDLC(JPacket packet, HDLC hdlc) {
		return hdlc.code() == 0x4242;
	}

	/**
	 * Gets the address value stored in this field
	 * 
	 * @return value of the field
	 */
	@Field(offset = 0, length = 1 * BYTE)
	public int address() {
		return super.getUByte(0);
	}

	/**
	 * Sets a new Address value within the field
	 * 
	 * @param value
	 *          new value
	 */
	public void address(int value) {
		super.setUByte(0, value);
	}

	/**
	 * Gets the value of the control field
	 * 
	 * @return value of stored in the field
	 */
	@Field(offset = 1 * BYTE, length = 1 * BYTE)
	public int control() {
		return super.getUByte(1);
	}

	/**
	 * Sets a new value for the control field
	 * 
	 * @param value
	 *          value to be stored in the field
	 */
	public void control(int value) {
		super.setUByte(0, value);
	}

	/**
	 * Value of the code field
	 * 
	 * @return the actual value in the code field
	 */
	@Field(offset = 2 * BYTE, length = 2 * BYTE)
	public int code() {
		return super.getUShort(2);
	}

	/**
	 * A more human friendly constant for the next protocol
	 * 
	 * @return return a enum constant or null if none matched
	 */
	public EthernetType codeEnum() {
		return EthernetType.valueOf(code());
	}

	/**
	 * Sets HDLC value for the next protocol linked to this HDLC header
	 * 
	 * @param value
	 *          EtherType type value
	 */
	public void code(int value) {
		super.setUShort(2, value);
	}

	/**
	 * Provides a more human friendly version of the checksum field. It
	 * specifically specifies if the checksum field matches the calcualated
	 * checksum.
	 * 
	 * @return more verbose description of the checksum field
	 */
	@Dynamic(Field.Property.DESCRIPTION)
	public String checksumDescription() {
		/*
		 * TODO: For now, we assume the frame has crc32, but we really need to check
		 * if its using CCIT 16-bit checksum as well.
		 */
		final int crc32 = calculateChecksumCRC32();
		if (checksum() == crc32) {
			return "correct";
		} else {
			return "incorrect: 0x" + Integer.toHexString(crc32).toUpperCase();
		}
	}

	/**
	 * Calculates a dynamic field offset for the checksum field at the end of the
	 * frame.
	 * 
	 * @return offset in bits of the checksum field
	 */
	@Dynamic(Field.Property.OFFSET)
	public int checksumOffset() {
		return (getPacket().size() - 4) * BYTE;
	}

	/**
	 * Reads the checksum field at the end of the frame
	 * 
	 * @return CRC32 or CCIT 16 crc value
	 */
	@Field(length = 4 * BYTE)
	public long checksum() {
		final JPacket packet = getPacket();
		return getUInt(packet.size() - 4); // 4 bytes from the end of the frame
	}

	/**
	 * Calculates the checksum for HDLC frame using address, control, code and
	 * payload
	 * 
	 * @return CRC32 checksum
	 */
	private int calculateChecksumCRC32() {
		final JPacket packet = getPacket();
		return Checksum.crc32CCITT(packet, 0, getPacket().size() - 4);
	}

	/**
	 * Calculates the checksum for HDLC frame using address, control, code and
	 * payload
	 * 
	 * @return CCIT 16-bit checksum
	 */
	@SuppressWarnings("unused")
	private int calculateChecksumCRC16CCITT() {
		final JPacket packet = getPacket();
		return Checksum.crc16CCITT(packet, 0, getPacket().size() - 2);
	}
}
