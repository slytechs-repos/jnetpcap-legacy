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

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Class SLL.
 */
@Header(length = SLL.SLL_HDR_LEN, suite = ProtocolSuite.LAN, description = "Linux Cooked Capture")
public class SLL
    extends
    JHeader {

	/** The Constant SLL_HDR_LEN. */
	public final static int SLL_HDR_LEN = 16;

	/** The Constant LINUX_SLL_HOST. */
	public final static int LINUX_SLL_HOST = 0;

	/** The Constant LINUX_SLL_BROADCAST. */
	public final static int LINUX_SLL_BROADCAST = 1;

	/** The Constant LINUX_SLL_MULTICAST. */
	public final static int LINUX_SLL_MULTICAST = 2;

	/** The Constant LINUX_SLL_OTHERHOST. */
	public final static int LINUX_SLL_OTHERHOST = 3;

	/** The Constant LINUX_SLL_OUTGOING. */
	public final static int LINUX_SLL_OUTGOING = 4;

	/** The ID. */
	public static int ID = JProtocol.SLL_ID;

	/**
	 * Packet type.
	 * 
	 * @return the int
	 */
	@Field(offset = 0, length = 16)
	public int packetType() {
		return super.getUShort(0);
	}

	/**
	 * Ha type.
	 * 
	 * @return the int
	 */
	@Field(offset = 16, length = 16)
	public int haType() {
		return super.getUShort(2);
	}

	/**
	 * The Enum HardwareAddressType.
	 */
	public enum HardwareAddressType {
		
		/** The LINU x_ sl l_ host. */
		LINUX_SLL_HOST,
		
		/** The LINU x_ sl l_ broadcast. */
		LINUX_SLL_BROADCAST,
		
		/** The LINU x_ sl l_ multicast. */
		LINUX_SLL_MULTICAST,
		
		/** The LINU x_ sl l_ otherhost. */
		LINUX_SLL_OTHERHOST,
		
		/** The LINU x_ sl l_ outgoing. */
		LINUX_SLL_OUTGOING,
	}

	/**
	 * Ha type enum.
	 * 
	 * @return the hardware address type
	 */
	public HardwareAddressType haTypeEnum() {
		return HardwareAddressType.values()[haType()];
	}

	/**
	 * Ha length.
	 * 
	 * @return the int
	 */
	@Field(offset = 32, length = 16)
	public int haLength() {
		return super.getUShort(4);
	}

	/**
	 * Address length.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	public int addressLength() {
		return haLength() * 8;
	}

	/**
	 * Address.
	 * 
	 * @return the byte[]
	 */
	@Field(offset = 48, format = "#mac#")
	public byte[] address() {
		return super.getByteArray(6, haLength());
	}

	/**
	 * Type.
	 * 
	 * @return the int
	 */
	@Field(offset = 112, length = 16, format = "%x")
	public int type() {
		return super.getUShort(14);
	}

	/**
	 * Type enum.
	 * 
	 * @return the ethernet. ethernet type
	 */
	public Ethernet.EthernetType typeEnum() {
		return Ethernet.EthernetType.valueOf(type());
	}
}
