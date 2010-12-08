/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.protocol.lan;

import java.nio.ByteOrder;
import java.util.List;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Format;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.Header.Characteristic;
import org.jnetpcap.packet.annotate.Header.Layer;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.checksum.Checksum;

/**
 * Ethernet2 definition. Datalink layer ethernet frame definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 14, dlt = {
		PcapDLT.EN10MB,
		PcapDLT.FDDI
}, osi = Layer.DATALINK, characteristics = Characteristic.CSMA_CD, nicname = "Eth", description = "Ethernet", url = "http://en.wikipedia.org/wiki/Ethernet")
public class Ethernet extends JHeader {

	/**
	 * A table of EtherType values and their names
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum EthernetType {
		IEEE_802DOT1Q(0x8100, "vlan - IEEE 802.1q"), IP4(0x800, "ip version 4"), IP6(
				0x86DD, "ip version 6"), ;
		public static String toString(int id) {
			for (EthernetType t : values()) {
				if (t.id == id) {
					return t.description;
				}
			}

			return null;
		}

		/**
		 * @param type
		 * @return
		 */
		public static EthernetType valueOf(int type) {
			for (EthernetType t : values()) {
				if (t.id == type) {
					return t;
				}
			}

			return null;
		}

		private final String description;

		private final int id;

		private EthernetType(int id) {
			this.id = id;
			this.description = name().toLowerCase();
		}

		private EthernetType(int id, String description) {
			this.id = id;
			this.description = description;

		}

		public final String getDescription() {
			return this.description;
		}

		public final int getId() {
			return this.id;
		}

	}

	public static final int ADDRESS_IG_BIT = 0x40;
	public static final int ADDRESS_LG_BIT = 0x80;
	public static final int ID = JProtocol.ETHERNET_ID;

	public static final int LENGTH = 14; // Ethernet header is 14 bytes long

	public static final String ORG_IEEE = "IEEE Ethernet2";

	@Field(offset = 0 * BYTE, length = 6 * BYTE, format = "#mac#", mask = 0xFFFF00000000L)
	public byte[] destination() {
		return getByteArray(0, 6);
	}

	@Field(parent = "destination", offset = 48 - 8, length = 1, display = "IG bit")
	@FlowKey(index = 0)
	public long destination_IG() {
		return (getUByte(0) & ADDRESS_IG_BIT) >> 5;
	}

	@Field(parent = "destination", offset = 48 - 7, length = 1, display = "LG bit")
	public long destination_LG() {
		return (getUByte(0) & ADDRESS_LG_BIT) >> 6;
	}

	public void destination(byte[] array) {
		setByteArray(0, array);
	}

	public byte[] destinationToByteArray(byte[] array) {
		return getByteArray(0, array);
	}

	@Field(offset = 6 * BYTE, length = 6 * BYTE, format = "#mac#", mask = 0xFFFF00000000L)
	@FlowKey(index = 0)
	public byte[] source() {
		return getByteArray(0 + 6, 6);
	}

	@Field(parent = "source", offset = 6 * BYTE - 8, length = 1, display = "IG bit")
	public long source_IG() {
		return (getUByte(0) & ADDRESS_IG_BIT) >> 5;
	}

	@Field(parent = "source", offset = 6 * BYTE - 7, length = 1, display = "LG bit")
	public long source_LG() {
		return (getUByte(0) & ADDRESS_LG_BIT) >> 6;
	}

	public void source(byte[] array) {
		setByteArray(0 + 6, array);
	}

	public byte[] sourceToByteArray(byte[] array) {
		return getByteArray(0 + 6, array);
	}

	@Field(offset = 12 * BYTE, length = 2 * BYTE, format = "%x")
	@FlowKey(index = 1)
	public int type() {
		return getUShort(0 + 12);
	}

	public void type(int type) {
		setUShort(0 + 12, type);
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String typeDescription() {
		return EthernetType.toString(type());
	}

	@Format
	public void formatHeader(List<JField> fields) {

	}

	public EthernetType typeEnum() {
		return EthernetType.valueOf(type());
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
