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

import java.util.EnumSet;
import java.util.Set;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderChecksum;
import org.jnetpcap.packet.annotate.BindingVariable;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.util.checksum.Checksum;

/**
 * Tcp/Ip header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
@SuppressWarnings("unused")
public class Tcp
    extends
    JHeader implements JHeaderChecksum {

	/**
	 * Constants for each TCP flag
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Flag {
		FIN,
		SYN,
		RST,
		PSH,
		ACK,
		URG,
		ECE,
		CWR, ;
		public static Set<Flag> asSet(int flags) {
			Set<Flag> set = EnumSet.noneOf(Tcp.Flag.class);
			final int len = values().length;

			for (int i = 0; i < len; i++) {
				if ((flags & (1 << i)) > 0) {
					set.add(values()[i]);
				}
			}

			return set;
		}

		public static String toCompactString(int flags) {
			return toCompactString(asSet(flags));
		}

		public static String toCompactString(Set<Flag> flags) {
			StringBuilder b = new StringBuilder(values().length);
			for (Flag f : flags) {
				b.append(f.name().charAt(0));
			}

			return b.toString();
		}
	}

	private static final int FLAG_ACK = 0x10;

	private static final int FLAG_CONG = 0x80;

	private static final int FLAG_CWR = 0x80;

	private static final int FLAG_ECE = 0x40;

	private static final int FLAG_ECN = 0x40;

	private static final int FLAG_FIN = 0x01;

	private static final int FLAG_PSH = 0x08;

	private static final int FLAG_RST = 0x04;

	private static final int FLAG_SYN = 0x02;

	private static final int FLAG_URG = 0x20;

	public static final int ID = JProtocol.TCP_ID;

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		final int hlen = (buffer.getUByte(offset + 12) & 0xF0) >> 4;
		return hlen * 4;
	}

	/**
	 * Hashcode computed
	 */
	private int biDirectionalHashcode;

	private Ip4 ip = new Ip4();

	/**
	 * Computed in decodeHeader. The hashcode is made up of IP address and port
	 * number using only the destination addresses. This creates a hashcode that
	 * is unique in a single direction.
	 */
	private int uniDirectionalHashcode;

	@Field(offset = 8 * BYTE, length = 16, format = "%x")
	public long ack() {
		return getUInt(8);
	}

	/**
	 * @param ack
	 */
	public void ack(long ack) {
		super.setUInt(8, ack);
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

	/**
	 * Retrieves the header's checksum.
	 * 
	 * @return header's stored checksum
	 */
	@Field(offset = 16 * BYTE, length = 16, format = "%x")
	public int checksum() {
		return getUShort(16);
	}

	/**
	 * @param crc
	 */
	public void checksum(int crc) {
		super.setUShort(16, crc);
	}

	private void clearFlag(int flag) {
		super.setUByte(13, flags() & ~flag);

	}

	@Override
	protected void decodeHeader() {
		/*
		 * Generate a bi-directional hashcode
		 */
		if (getPacket() != null && getPacket().hasHeader(ip)) {
			this.biDirectionalHashcode =
			    (ip.destinationToInt() + destination())
			        ^ (ip.sourceToInt() + source());

			this.uniDirectionalHashcode = (ip.destinationToInt() + destination());

		} else {
			this.biDirectionalHashcode = super.hashCode();
		}
	}

	@BindingVariable
	@Field(offset = 16, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int destination() {
		return getUShort(2);
	}

	public void destination(int dst) {
		super.setUShort(2, dst);
	}

	@Field(offset = 13 * BYTE, length = 8, format = "%x")
	public int flags() {
		return getUByte(13);
	}

	public void flags(int flags) {
		super.setUByte(13, flags);
	}

	/**
	 * @return
	 */
	@Field(parent = "flags", offset = 4, length = 1, format = "%b", display = "ack", description = "acknowledgment")
	public boolean flags_ACK() {
		return (flags() & FLAG_ACK) != 0;
	}

	/**
	 * @param flag
	 */
	public void flags_ACK(boolean flag) {
		setFlag(flag, FLAG_ACK);
	}

	@Field(parent = "flags", offset = 7, length = 1, format = "%b", display = "cwr", description = "reduced (cwr)")
	public boolean flags_CWR() {
		return (flags() & FLAG_CWR) != 0;
	}

	public void flags_CWR(boolean flag) {
		setFlag(flag, FLAG_CWR);
	}

	@Field(parent = "flags", offset = 6, length = 1, format = "%b", display = "ece", description = "ECN echo flag")
	public boolean flags_ECE() {
		return (flags() & FLAG_ECE) != 0;
	}

	public void flags_ECE(boolean flag) {
		setFlag(flag, FLAG_ECE);
	}

	@Field(parent = "flags", offset = 0, length = 1, format = "%b", display = "fin", description = "closing down connection")
	public boolean flags_FIN() {
		return (flags() & FLAG_FIN) != 0;
	}

	public void flags_FIN(boolean flag) {
		setFlag(flag, FLAG_FIN);
	}

	@Field(parent = "flags", offset = 3, length = 1, format = "%b", display = "ack", description = "push current segment of data")
	public boolean flags_PSH() {
		return (flags() & FLAG_PSH) != 0;
	}

	public void flags_PSH(boolean flag) {
		setFlag(flag, FLAG_PSH);
	}

	@Field(parent = "flags", offset = 2, length = 1, format = "%b", display = "ack", description = "reset connection")
	public boolean flags_RST() {
		return (flags() & FLAG_RST) != 0;
	}

	public void flags_RST(boolean flag) {
		setFlag(flag, FLAG_RST);
	}

	@Field(parent = "flags", offset = 1, length = 1, format = "%b", display = "ack", description = "synchronize connection, startup")
	public boolean flags_SYN() {
		return (flags() & FLAG_SYN) != 0;
	}

	public void flags_SYN(boolean flag) {
		setFlag(flag, FLAG_SYN);
	}

	@Field(parent = "flags", offset = 5, length = 1, format = "%b", display = "ack", description = "urgent, out-of-band data")
	public boolean flags_URG() {
		return (flags() & FLAG_URG) != 0;
	}

	/**
	 * @param b
	 */
	public void flags_URG(boolean flag) {
		setFlag(flag, FLAG_URG);
	}

	public String flagsCompactString() {
		return Flag.toCompactString(flags());
	}

	/**
	 * @return
	 */
	public Set<Flag> flagsEnum() {
		return Flag.asSet(flags());
	}

	/**
	 * Calculates the length of the TCP payload.
	 * 
	 * @return length of tcp segment data in bytes
	 */
	public int getPayloadLength() {
		getPacket().getHeader(ip);
		return ip.length() - ip.hlen() * 4 - hlen() * 4;
	}

	/**
	 * Returns a bi-directional hashcode for this header. The hashcode is made up
	 * of IP source, IP destination, Tcp source and destination port numbers. It
	 * is created in a such a way that packet's source and destination fields are
	 * interchangable and will generate the same hashcode.
	 * 
	 * @return bi-directional hashcode for this TCP/IP header combination
	 * @see #uniHashCode()
	 */
	@Override
	public int hashCode() {
		return this.biDirectionalHashcode;
	}

	@Field(offset = 12 * BYTE, length = 4)
	public int hlen() {
		return (getUByte(12) & 0xF0) >> 4;
	}

	/**
	 * @param length
	 *          in 4 byte words
	 */
	public void hlen(int length) {
		super.setUByte(12, ((getUByte(12) & 0x0F) | (length << 4)));
	}

	@Field(offset = 12 * BYTE + 4, length = 4)
	public int reserved() {
		return getUByte(12) & 0x0F;
	}

	@Field(offset = 4 * BYTE, length = 16, format = "%x")
	public long seq() {
		return getUInt(4);
	}

	/**
	 * @param seq
	 */
	public void seq(long seq) {
		super.setUInt(4, seq);
	}

	private void setFlag(boolean state, int flag) {
		if (state) {
			setFlag(flag);
		} else {
			clearFlag(flag);
		}
	}

	private void setFlag(int flag) {
		super.setUByte(13, flags() | flag);
	}

	@BindingVariable
	@Field(offset = 0, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int source() {
		return getUShort(0);
	}

	public void source(int src) {
		super.setUShort(0, src);
	}

	/**
	 * Uni-directional hashcode. A hashcode that is computed based on IP
	 * destination and TCP destination port. This make the hashcode uni-direction
	 * in the direction from source to destination.
	 * 
	 * @return a hashcode that is uni-directional
	 */
	public int uniHashCode() {
		return this.uniDirectionalHashcode;
	}

	@Field(offset = 18 * BYTE, length = 16)
	public int urgent() {
		return getUShort(18);
	}

	/**
	 * @param urg
	 */
	public void urgent(int urg) {
		super.setUShort(18, urg);
	}

	@Field(offset = 14 * BYTE, length = 16)
	public int window() {
		return getUShort(14);
	}

	public void window(int win) {
		super.setUShort(14, win);
	}

	public int windowScaled() {
		return window() << 6;
	}

	/**
	 * Calculates a checksum using protocol specification for a header. Checksums
	 * for partial headers or fragmented packets (unless the protocol alows it)
	 * are not calculated.
	 * 
	 * @return header's calculated checksum
	 */
	public int calculateChecksum() {

		if (getIndex() == -1) {
			throw new IllegalStateException("Oops index not set");
		}

		final int ipOffset = getPreviousHeaderOffset();

		return Checksum.inChecksumShouldBe(checksum(), Checksum.pseudoTcp(packet,
		    ipOffset, this.getOffset()));
	}

	/**
	 * Checks if the checksum is valid, for un-fragmented packets. If a packet is
	 * fragmented, the checksum is not verified as data to is incomplete, but the
	 * method returns true none the less.
	 * 
	 * @return true if checksum checks out or if this is a fragment, otherwise if
	 *         the computed checksum does not match the stored checksum false is
	 *         returned
	 */
	public boolean isChecksumValid() {

		if (isFragmented()) {
			return true;
		}

		if (getIndex() == -1) {
			throw new IllegalStateException("Oops index not set");
		}

		final int ipOffset = getPreviousHeaderOffset();

		return Checksum.pseudoTcp(packet, ipOffset, this.getOffset()) == 0;
	}
}
