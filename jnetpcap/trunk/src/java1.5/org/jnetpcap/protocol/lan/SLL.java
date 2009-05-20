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
package org.jnetpcap.protocol.lan;

import java.nio.ByteOrder;

import org.jnetpcap.PcapDLT;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.JScan;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.packet.annotate.Scanner;
import org.jnetpcap.protocol.JProtocol;

/**
 * For captures on Linux cooked sockets, we construct a fake header that
 * includes: a 2-byte "packet type" which is one of: LINUX_SLL_HOST packet was
 * sent to us LINUX_SLL_BROADCAST packet was broadcast LINUX_SLL_MULTICAST
 * packet was multicast LINUX_SLL_OTHERHOST packet was sent to somebody else
 * LINUX_SLL_OUTGOING packet was sent *by* us; a 2-byte Ethernet protocol field;
 * a 2-byte link-layer type; a 2-byte link-layer address length; an 8-byte
 * source link-layer address, whose actual length is specified by the previous
 * value. All fields except for the link-layer address are in network byte
 * order. DO NOT change the layout of this structure, or change any of the
 * LINUX_SLL_ values below. If you must change the link-layer header for a
 * "cooked" Linux capture, introduce a new DLT_ type (ask
 * "tcpdump-workers@lists.tcpdump.org" for one, so that you don't give it a
 * value that collides with a value already being used), and use the new header
 * in captures of that type, so that programs that can handle DLT_LINUX_SLL
 * captures will continue to handle them correctly without any change, and so
 * that capture files with different headers can be told apart and programs that
 * read them can dissect the packets in them.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * 
 * <pre>
 *  #define SLL_HDR_LEN	16		          // total header length
 *  #define SLL_ADDRLEN	8		            // length of address field
 * 
 *  struct sll_header {
 *    u_int16_t	sll_pkttype;	          // packet type
 *    u_int16_t	sll_hatype;	            // link-layer address type
 *    u_int16_t	sll_halen;	            // link-layer address length
 *    u_int8_t	sll_addr[SLL_ADDRLEN];	// link-layer address
 *    u_int16_t	sll_protocol;         	// protocol
 *  };
 * 
 * </pre>
 */
@Header(dlt = PcapDLT.LINUX_SLL, length = SLL.SLL_HDR_LEN, suite = ProtocolSuite.LAN, description = "Linux Cooked Capture")
public class SLL
    extends
    JHeader {

	public final static int SLL_HDR_LEN = 16;

	public final static int LINUX_SLL_HOST = 0;

	public final static int LINUX_SLL_BROADCAST = 1;

	public final static int LINUX_SLL_MULTICAST = 2;

	public final static int LINUX_SLL_OTHERHOST = 3;

	public final static int LINUX_SLL_OUTGOING = 4;

	public static int ID;

	static {
		ID = register();
	}

	/**
	 * Register our header dynamicly the first time its referenced. Report syntax
	 * errors if there is a problem.
	 * 
	 * @return ID assigned by the registry.
	 */
	private static int register() {
		try {
			return (JRegistry.register(SLL.class));
		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}

	}
	
	public SLL() {
		super.order(ByteOrder.BIG_ENDIAN);
	}

//	 @Bind(from = Ip4.class, to = SLL.class)
//	 public static boolean bindIp4ToSLL(JPacket packet, SLL sll) {
//	 return sll.type() == 0x800;
//	 }

	@Scanner
	public static void scanner(JScan scan) {

		JBuffer buf = scan.scan_packet();
		buf.order(ByteOrder.BIG_ENDIAN);
		int offset = scan.scan_offset();

		switch (buf.getUShort(offset + 14)) {
			case 0x800: // Ip4
				scan.scan_length(16);
				scan.scan_next_id(JProtocol.IP4_ID);
				break;
		}
	}

	/**
	 * Packet type
	 * 
	 * @return packet type
	 */
	@Field(offset = 0, length = 16)
	public int packetType() {
		return super.getUShort(0);
	}

	/**
	 * Link Layer address type
	 * 
	 * @return address type
	 */
	@Field(offset = 16, length = 16)
	public int haType() {
		return super.getUShort(2);
	}

	public enum HardwareAddressType {
		LINUX_SLL_HOST,
		LINUX_SLL_BROADCAST,
		LINUX_SLL_MULTICAST,
		LINUX_SLL_OTHERHOST,
		LINUX_SLL_OUTGOING,
	}

	public HardwareAddressType haTypeEnum() {
		return HardwareAddressType.values()[haType()];
	}

	/**
	 * Link Layer address length
	 * 
	 * @return address length in bytes
	 */
	@Field(offset = 32, length = 16)
	public int haLength() {
		return super.getUShort(4);
	}

	/**
	 * Link Layer address length
	 * 
	 * @return address length in bits
	 */
	@Dynamic(Field.Property.LENGTH)
	public int addressLength() {
		return haLength() * 8;
	}

	/**
	 * Link layer address
	 * 
	 * @return address
	 */
	@Field(offset = 48, format = "#mac#")
	public byte[] address() {
		int haLen = haLength();
		System.out.println(this.toHexdump());
		return super.getByteArray(6, haLength());
	}

	/**
	 * next protocol
	 * 
	 * @return next protocol
	 */
	@Field(offset = 112, length = 16, format = "%x")
	public int type() {
		return super.getUShort(14);
	}

	/**
	 * Next protocol as an EtherType constant
	 * 
	 * @return next protocol
	 */
	public Ethernet.EthernetType typeEnum() {
		return Ethernet.EthernetType.valueOf(type());
	}
}