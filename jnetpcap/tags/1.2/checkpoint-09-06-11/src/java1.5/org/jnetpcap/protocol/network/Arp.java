/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;

/**
 * Address Resolution Protocol header. ARP is used to translate protocol
 * addresses to hardware interface addresses.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
public class Arp
    extends
    JHeader {

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		final int hlen = buffer.getUByte(offset + 4);
		final int plen = buffer.getUByte(offset + 5);

		return (hlen + plen) * 2 + 8;
	}

	private int shaOffset;

	private int spaOffset;

	private int thaOffset;

	private int tpaOffset;

	/**
	 * Definitions for ARP supported hardware types
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum HardwareType {
		RESERVED1,
		ETHERNET,
		EXSPERIMENTAL_ETHERNET,
		AMATEUR_RADIO_AX_25,
		PROTEON_PRO_NET_TOKEN_RING,
		CHAOS,
		IEEE802,
		ARCNET,
		HYPERCHANNEL,
		LANSTAR,
		AUTONET_SHORT_ADDRESS,
		LOCAL_TALK,
		LOCAL_NET,
		ULTRA_LINK,
		SMDS,
		FRAME_RELAY,
		ATM1,
		SERIAL_LINE,
		ATM2,
		MIL_STD_188_220,
		METRICOM,
		IEEE1395,
		MAPOS,
		TWINAXIAL,
		EUI64,
		HIPARP,
		ISO7816_3,
		ARPSEC,
		IPSEC_TUNNEL,
		INFINIBAND,
		CAI,
		WIEGAND_INTERFACE,
		PURE_ID,
		HW_EXP1, ;

		/**
		 * Convert a numerical protocol type number to constant
		 * 
		 * @param value
		 *          value of the protocol type field
		 * @return corresponding constant or null if none matched
		 */
		public static HardwareType valueOf(int value) {
			return values()[value];
		}
	}

	/**
	 * Definitions for supported protocol types
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc@SuppressWarnings("unused") .
	 */
	public enum ProtocolType {
		IP(0x800);

		@SuppressWarnings("unused")
		private final int value;

		private ProtocolType(int value) {
			this.value = value;
		}

		/**
		 * Convert a numerical protocol type number to constant
		 * 
		 * @param value
		 *          value of the protocol type field
		 * @return corresponding constant or null if none matched
		 */
		public static ProtocolType valueOf(int value) {
			if (value == 0x800) {
				return IP;
			}

			return null;
		}
	}

	/**
	 * Definitions for all the possible ARP operations as specified by the
	 * operation field.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum OpCode {
		RESERVED1,
		REQUEST,
		REPLY,
		REQUEST_REVERSE,
		REPLY_REVERSE,
		DRARP_REQUEST,
		DRARP_REPLY,
		DRARP_ERROR,
		IN_ARP_REQUEST,
		IN_ARP_REPLY,
		ARP_NAK,
		MARS_REQUEST,
		MARS_MULTI,
		MARS_MSERV,
		MARS_JOIN,
		MARS_LEAVE,
		MARS_NAK,
		MARS_UNSERV,
		MARS_SJOIN,
		MARS_SLEAVE,
		MARS_GROUP_LIST_REQUEST,
		MARS_GROUP_LIST_REPLAY,
		MARS_REDIRECT_MAP,
		MAPOS_UNARP,
		OP_EXP1,
		OP_EXP2, ;

		/**
		 * Converts the operation field value to a constant
		 * 
		 * @param value
		 *          operation field value
		 * @return constant or null
		 */
		public static OpCode valueOf(int value) {
			return values()[value];
		}
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String hardwareTypeDescription() {
		return hardwareTypeEnum().toString();
	}

	@Field(offset = 0, length = 16)
	public int hardwareType() {
		return super.getUShort(0);
	}

	public HardwareType hardwareTypeEnum() {
		return HardwareType.valueOf(hardwareType());
	}

	@Field(offset = 2 * 8, format = "%x", length = 16)
	public int protocolType() {
		return super.getUShort(2);
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String protocolTypeDescription() {
		return protocolTypeEnum().toString();
	}

	public ProtocolType protocolTypeEnum() {
		return ProtocolType.valueOf(protocolType());
	}

	@Field(offset = 4 * 8, length = 8, units = "bytes", display = "hardware size")
	public int hlen() {
		return super.getUByte(4);
	}

	@Field(offset = 5 * 8, length = 8, units = "bytes", display = "protocol size")
	public int plen() {
		return super.getUByte(5);
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String operationDescription() {
		return operationEnum().toString();
	}

	@Field(offset = 6 * 8, length = 16, display = "op code")
	public int operation() {
		return super.getUShort(6);
	}

	public OpCode operationEnum() {
		return OpCode.valueOf(operation());
	}

	@Field(offset = 8 * 8, format = "#mac#", display = "sender MAC")
	public byte[] sha() {
		return super.getByteArray(this.shaOffset, hlen());
	}

	@Dynamic(Field.Property.LENGTH)
	public int shaLength() {
		return hlen() * 8;
	}

	@Field(format = "#ip4#", display = "sender IP")
	public byte[] spa() {
		return super.getByteArray(this.spaOffset, plen());
	}

	@Dynamic(Field.Property.OFFSET)
	public int spaOffset() {
		return this.spaOffset * 8;
	}

	@Dynamic(Field.Property.LENGTH)
	public int spaLength() {
		return plen() * 8;
	}

	@Field(format = "#mac#", display = "target MAC")
	public byte[] tha() {
		return super.getByteArray(this.thaOffset, hlen());
	}

	@Dynamic(Field.Property.OFFSET)
	public int thaOffset() {
		return this.thaOffset * 8;
	}

	@Dynamic(Field.Property.LENGTH)
	public int thaLength() {
		return hlen() * 8;
	}

	@Field(format = "#ip4#", display = "target IP")
	public byte[] tpa() {
		return super.getByteArray(this.tpaOffset, plen());
	}

	@Dynamic(Field.Property.OFFSET)
	public int tpaOffset() {
		return this.tpaOffset * 8;
	}

	@Dynamic(Field.Property.LENGTH)
	public int tpaLength() {
		return plen() * 8;
	}

	@Override
	protected void decodeHeader() {

		/*
		 * Pre calculate offsets for variable length fields
		 */
		final int hlen = hlen();
		final int plen = plen();

		this.shaOffset = 8;
		this.spaOffset = shaOffset + hlen;

		this.thaOffset = spaOffset + plen;
		this.tpaOffset = thaOffset + hlen;
	}

}
