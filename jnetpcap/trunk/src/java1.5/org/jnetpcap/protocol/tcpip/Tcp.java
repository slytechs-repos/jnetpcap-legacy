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
 * Transmission Control Protocol (TCP).
 * <p>
 * The Transmission Control Protocol (TCP) is one of the core protocols of the
 * Internet Protocol Suite. TCP is one of the two original components of the
 * suite, complementing the Internet Protocol (IP) and therefore the entire
 * suite is commonly referred to as TCP/IP. TCP provides the service of
 * exchanging data reliably directly between two network hosts, whereas IP
 * handles addressing and routing message across one or more networks. In
 * particular, TCP provides reliable, ordered delivery of a stream of bytes from
 * a program on one computer to another program on another computer. TCP is the
 * protocol that major Internet applications rely on, such as the World Wide
 * Web, e-mail, and file transfer. Other applications, which do not require
 * reliable data stream service, may use the User Datagram Protocol (UDP) which
 * provides a datagram service, which emphasizes reduced latency over
 * reliability.
 * </p>
 * <p>
 * A TCP segment consists of a segment header and a data section. The TCP header
 * contains 10 mandatory fields, and an optional extension field (Options).
 * </p>
 * <p>
 * The data section follows the header. Its contents are the payload data
 * carried for the application. The length of the data section is not specified
 * in the TCP segment header. It can be calculated by subtracting the combined
 * length of the TCP header and the encapsulating IP segment header from the
 * total IP segment length (specified in the IP segment header).
 * </p>
 * <p>
 * The header structure is as follows:
 * <ul>
 * <li> Source port (16 bits) – identifies the sending port
 * <li> Destination port (16 bits) – identifies the receiving port
 * <li> Sequence number (32 bits) – has a dual role:
 * <ul>
 * <li> If the SYN flag is set, then this is the initial sequence number. The
 * sequence number of the actual first data byte (and the acknowledged number in
 * the corresponding ACK) are then this sequence number plus 1.
 * <li> If the SYN flag is clear, then this is the accumulated sequence number
 * of the first data byte of this packet for the current session.
 * </ul>
 * <li> Acknowledgment number (32 bits) – if the ACK flag is set then the value
 * of this field is the next sequence number that the receiver is expecting.
 * This acknowledges receipt of all prior bytes (if any). The first ACK sent by
 * each end acknowledges the other end's initial sequence number itself, but no
 * data.
 * <li> Data offset (4 bits) – specifies the size of the TCP header in 32-bit
 * words. The minimum size header is 5 words and the maximum is 15 words thus
 * giving the minimum size of 20 bytes and maximum of 60 bytes, allowing for up
 * to 40 bytes of options in the header. This field gets its name from the fact
 * that it is also the offset from the start of the TCP segment to the actual
 * data.
 * <li> Reserved (4 bits) – for future use and should be set to zero
 * <li> Flags (8 bits) (aka Control bits) – contains 8 1-bit flags
 * <ul>
 * <li> CWR (1 bit) – Congestion Window Reduced (CWR) flag is set by the sending
 * host to indicate that it received a TCP segment with the ECE flag set and had
 * responded in congestion control mechanism (added to header by RFC 3168).
 * <li> ECE (1 bit) – ECN-Echo indicates If the SYN flag is set, that the TCP
 * peer is ECN capable. If the SYN flag is clear, that a packet with Congestion
 * Experienced flag in IP header set is received during normal transmission
 * (added to header by RFC 3168).
 * <li>URG (1 bit) – indicates that the Urgent pointer field is significant
 * <li>ACK (1 bit) – indicates that the Acknowledgment field is significant.
 * All packets after the initial SYN packet sent by the client should have this
 * flag set.
 * <li>PSH (1 bit) – Push function. Asks to push the buffered data to the
 * receiving application.
 * <li>RST (1 bit) – Reset the connection
 * <li>SYN (1 bit) – Synchronize sequence numbers. Only the first packet sent
 * from each end should have this flag set. Some other flags change meaning
 * based on this flag, and some are only valid for when it is set, and others
 * when it is clear.
 * <li>FIN (1 bit) – No more data from sender
 * </ul>
 * <li> Window (16 bits) – the size of the receive window, which specifies the
 * number of bytes (beyond the sequence number in the acknowledgment field) that
 * the receiver is currently willing to receive (see Flow control and Window
 * Scaling)
 * <li> Checksum (16 bits) – The 16-bit checksum field is used for
 * error-checking of the header and data
 * <li> Urgent pointer (16 bits) – if the URG flag is set, then this 16-bit
 * field is an offset from the sequence number indicating the last urgent data
 * byte
 * <li> Options (Variable 0-320 bits, divisible by 32) – The length of this
 * field is determined by the data offset field. Options 0 and 1 are a single
 * byte (8 bits) in length. The remaining options indicate the total length of
 * the option (expressed in bytes) in the second byte. Some options may only be
 * sent when SYN is set; they are indicated below as [SYN].
 * <ul>
 * <li> 0 (8 bits) - End of options list
 * <li> 1 (8 bits) - No operation (NOP, Padding) This may be used to align
 * option fields on 32-bit boundaries for better performance.
 * <li>2,4,SS (32 bits) - Maximum segment size (see maximum segment size) [SYN]
 * <li>3,3,S (24 bits) - Window scale (see window scaling for details) [SYN]
 * <li>4,2 (16 bits) - Selective Acknowledgement permitted. [SYN] (See
 * selective acknowledgments for details)
 * <li>5,N,BBBB,EEEE,... (variable bits, N is either 10, 18, 26, or 34)-
 * Selective ACKnowlegement (SACK) These first two bytes are followed by a list
 * of 1-4 blocks being selectively acknowledged, specified as 32-bit begin/end
 * pointers.
 * <li>8,10,TTTT,EEEE (80 bits)- Timestamp and echo of previous timestamp (see
 * TCP Timestamps for details)
 * <li>14,3,S (24 bits) - TCP Alternate Checksum Request. [SYN]
 * <li>15,N,... (variable bits) - TCP Alternate Checksum Data.
 * </ul>
 * </ul>
 * (The remaining options are obsolete, experimental, not yet standardized, or
 * unassigned)
 * </p>
 * Description source: http://wikipedia.org/wiki/Tcp_protocol
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
	 * Flags (8 bits) (aka Control bits) – contains 8 1-bit flags
	 * <ul>
	 * <li> CWR (1 bit) – Congestion Window Reduced (CWR) flag is set by the
	 * sending host to indicate that it received a TCP segment with the ECE flag
	 * set and had responded in congestion control mechanism (added to header by
	 * RFC 3168).
	 * <li> ECE (1 bit) – ECN-Echo indicates If the SYN flag is set, that the TCP
	 * peer is ECN capable. If the SYN flag is clear, that a packet with
	 * Congestion Experienced flag in IP header set is received during normal
	 * transmission (added to header by RFC 3168).
	 * <li>URG (1 bit) – indicates that the Urgent pointer field is significant
	 * <li>ACK (1 bit) – indicates that the Acknowledgment field is significant.
	 * All packets after the initial SYN packet sent by the client should have
	 * this flag set.
	 * <li>PSH (1 bit) – Push function. Asks to push the buffered data to the
	 * receiving application.
	 * <li>RST (1 bit) – Reset the connection
	 * <li>SYN (1 bit) – Synchronize sequence numbers. Only the first packet sent
	 * from each end should have this flag set. Some other flags change meaning
	 * based on this flag, and some are only valid for when it is set, and others
	 * when it is clear.
	 * <li>FIN (1 bit) – No more data from sender
	 * </ul>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Flag {
		/**
		 * ACK (1 bit) – indicates that the Acknowledgment field is significant. All
		 * packets after the initial SYN packet sent by the client should have this
		 * flag set.
		 */
		ACK,
		/**
		 * CWR (1 bit) – Congestion Window Reduced (CWR) flag is set by the sending
		 * host to indicate that it received a TCP segment with the ECE flag set and
		 * had responded in congestion control mechanism (added to header by RFC
		 * 3168).
		 */
		CWR,
		/**
		 * ECE (1 bit) – ECN-Echo indicates If the SYN flag is set, that the TCP
		 * peer is ECN capable. If the SYN flag is clear, that a packet with
		 * Congestion Experienced flag in IP header set is received during normal
		 * transmission (added to header by RFC 3168).
		 */
		ECE,
		/**
		 * FIN (1 bit) – No more data from sender
		 */
		FIN,
		/**
		 * PSH (1 bit) – Push function. Asks to push the buffered data to the
		 * receiving application.
		 */
		PSH,
		/**
		 * RST (1 bit) – Reset the connection
		 */
		RST,
		/**
		 * SYN (1 bit) – Synchronize sequence numbers. Only the first packet sent
		 * from each end should have this flag set. Some other flags change meaning
		 * based on this flag, and some are only valid for when it is set, and
		 * others when it is clear.
		 */
		SYN,
		/**
		 * URG (1 bit) – indicates that the Urgent pointer field is significant
		 */
		URG, ;

		/**
		 * Converts 8 contigeous bits of an inteteger to a set collection of enum
		 * constants, each representing if a flag is set in the original integer.
		 * 
		 * @param flags
		 *          integer containing the flags (8-bits)
		 * @return a collection set with constants for each bit set within the
		 *         integer
		 */
		public static Set<Flag> asSet(final int flags) {
			final Set<Flag> set = EnumSet.noneOf(Tcp.Flag.class);
			final int len = values().length;

			for (int i = 0; i < len; i++) {
				if ((flags & (1 << i)) > 0) {
					set.add(values()[i]);
				}
			}

			return set;
		}

		/**
		 * Returns a compact string representation of the bit flags that are set
		 * within the integer.
		 * 
		 * @param flags
		 *          integer containing the flags (8-bit)
		 * @return a terse representation of the flags
		 */
		public static String toCompactString(final int flags) {
			return toCompactString(asSet(flags));
		}

		/**
		 * Returns a compact string representation of the flags contained with the
		 * collection's set
		 * 
		 * @param flags
		 *          a collection's set of flags
		 * @return a terse representation of the flags
		 */
		public static String toCompactString(final Set<Flag> flags) {
			final StringBuilder b = new StringBuilder(values().length);
			for (final Flag f : flags) {
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

	/**
	 * Unique numerical ID for this protocol header definition
	 */
	public static final int ID = JProtocol.TCP_ID;

	/**
	 * Calculates the length of a tcp header
	 * 
	 * @param buffer
	 *          buffer containing packet and/or tcp header data
	 * @param offset
	 *          offset into the buffer where tcp header start (in bytes)
	 * @return number of bytes occupied by the tcp header, including any tcp
	 *         options
	 */
	@HeaderLength
	public static int headerLength(final JBuffer buffer, final int offset) {
		final int hlen = (buffer.getUByte(offset + 12) & 0xF0) >> 4;
		return hlen * 4;
	}

	/**
	 * Hashcode computed
	 */
	private int biDirectionalHashcode;

	private final Ip4 ip = new Ip4();

	/**
	 * Computed in decodeHeader. The hashcode is made up of IP address and port
	 * number using only the destination addresses. This creates a hashcode that
	 * is unique in a single direction.
	 */
	private int uniDirectionalHashcode;

	/**
	 * Acknowledgment number (32 bits). If the ACK flag is set then the value of
	 * this field is the next sequence number that the receiver is expecting. This
	 * acknowledges receipt of all prior bytes (if any). The first ACK sent by
	 * each end acknowledges the other end's initial sequence number itself, but
	 * no data.
	 * 
	 * @return the value of the field
	 */
	@Field(offset = 8 * BYTE, length = 16, format = "%x")
	public long ack() {
		return getUInt(8);
	}

	/**
	 * @param ack
	 */
	public void ack(final long ack) {
		super.setUInt(8, ack);
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

		return Checksum.inChecksumShouldBe(checksum(), Checksum.pseudoTcp(
		    this.packet, ipOffset, getOffset()));
	}

	/**
	 * Checksum (16 bits). The 16-bit checksum field is used for error-checking of
	 * the header and data .
	 * 
	 * @return the field's value
	 */
	@Field(offset = 16 * BYTE, length = 16, format = "%x")
	public int checksum() {
		return getUShort(16);
	}

	/**
	 * @param crc
	 */
	public void checksum(final int crc) {
		super.setUShort(16, crc);
	}

	/**
	 * Returns a dynamic description of the checksum field. Specifically it checks
	 * and displays, as description, the state of the checksum field, if it
	 * matches the calculated checksum or not.
	 * 
	 * @return additional information about the state of the checksum field
	 */
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

	private void clearFlag(int flag) {
		super.setUByte(13, flags() & ~flag);

	}

	@Override
	protected void decodeHeader() {
		/*
		 * Generate a bi-directional hashcode
		 */
		if ((getPacket() != null) && getPacket().hasHeader(this.ip)) {
			this.biDirectionalHashcode =
			    (this.ip.destinationToInt() + destination())
			        ^ (this.ip.sourceToInt() + source());

			this.uniDirectionalHashcode =
			    (this.ip.destinationToInt() + destination());

		} else {
			this.biDirectionalHashcode = super.hashCode();
		}
	}

	/**
	 * Destination port (16 bits). Identifies the receiving port
	 * 
	 * @return the field's value
	 */
	@BindingVariable
	@Field(offset = 16, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int destination() {
		return getUShort(2);
	}

	/**
	 * Sets a new value for the destination field
	 * 
	 * @param value
	 *          new value for the field
	 */
	public void destination(final int value) {
		super.setUShort(2, value);
	}

	/**
	 * Flags (8 bits) (aka Control bits) – contains 8 1-bit flags
	 * <ul>
	 * <li> CWR (1 bit) – Congestion Window Reduced (CWR) flag is set by the
	 * sending host to indicate that it received a TCP segment with the ECE flag
	 * set and had responded in congestion control mechanism (added to header by
	 * RFC 3168).
	 * <li> ECE (1 bit) – ECN-Echo indicates If the SYN flag is set, that the TCP
	 * peer is ECN capable. If the SYN flag is clear, that a packet with
	 * Congestion Experienced flag in IP header set is received during normal
	 * transmission (added to header by RFC 3168).
	 * <li>URG (1 bit) – indicates that the Urgent pointer field is significant
	 * <li>ACK (1 bit) – indicates that the Acknowledgment field is significant.
	 * All packets after the initial SYN packet sent by the client should have
	 * this flag set.
	 * <li>PSH (1 bit) – Push function. Asks to push the buffered data to the
	 * receiving application.
	 * <li>RST (1 bit) – Reset the connection
	 * <li>SYN (1 bit) – Synchronize sequence numbers. Only the first packet sent
	 * from each end should have this flag set. Some other flags change meaning
	 * based on this flag, and some are only valid for when it is set, and others
	 * when it is clear.
	 * <li>FIN (1 bit) – No more data from sender
	 * </ul>
	 * 
	 * @return the field's value
	 */
	@Field(offset = 13 * BYTE, length = 8, format = "%x")
	public int flags() {
		return getUByte(13);
	}

	/**
	 * Sets a new value for the flags field (8-bits)
	 * 
	 * @param value
	 *          new value for the field
	 */
	public void flags(final int value) {
		super.setUByte(13, value);
	}

	/**
	 * ACK (1 bit) – indicates that the Acknowledgment field is significant. All
	 * packets after the initial SYN packet sent by the client should have this
	 * flag set.
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(parent = "flags", offset = 4, length = 1, format = "%b", display = "ack", description = "acknowledgment")
	public boolean flags_ACK() {
		return (flags() & FLAG_ACK) != 0;
	}

	/**
	 * Sets new value for the bit flag
	 * 
	 * @param value
	 *          sets the flag bit, false clears it
	 */
	public void flags_ACK(final boolean value) {
		setFlag(value, FLAG_ACK);
	}

	/**
	 * CWR (1 bit) – Congestion Window Reduced (CWR) flag is set by the sending
	 * host to indicate that it received a TCP segment with the ECE flag set and
	 * had responded in congestion control mechanism (added to header by RFC
	 * 3168).
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(parent = "flags", offset = 7, length = 1, format = "%b", display = "cwr", description = "reduced (cwr)")
	public boolean flags_CWR() {
		return (flags() & FLAG_CWR) != 0;
	}

	/**
	 * Sets new value for the bit flag
	 * 
	 * @param value
	 *          sets the flag bit, false clears it
	 */
	public void flags_CWR(final boolean value) {
		setFlag(value, FLAG_CWR);
	}

	/**
	 * ECE (1 bit) – ECN-Echo indicates If the SYN flag is set, that the TCP peer
	 * is ECN capable. If the SYN flag is clear, that a packet with Congestion
	 * Experienced flag in IP header set is received during normal transmission
	 * (added to header by RFC 3168).
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(parent = "flags", offset = 6, length = 1, format = "%b", display = "ece", description = "ECN echo flag")
	public boolean flags_ECE() {
		return (flags() & FLAG_ECE) != 0;
	}

	/**
	 * Sets new value for the bit flag
	 * 
	 * @param value
	 *          sets the flag bit, false clears it
	 */
	public void flags_ECE(final boolean value) {
		setFlag(value, FLAG_ECE);
	}

	/**
	 * FIN (1 bit) – No more data from sender
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(parent = "flags", offset = 0, length = 1, format = "%b", display = "fin", description = "closing down connection")
	public boolean flags_FIN() {
		return (flags() & FLAG_FIN) != 0;
	}

	/**
	 * Sets new value for the bit flag
	 * 
	 * @param value
	 *          sets the flag bit, false clears it
	 */
	public void flags_FIN(final boolean value) {
		setFlag(value, FLAG_FIN);
	}

	/**
	 * PSH (1 bit) – Push function. Asks to push the buffered data to the
	 * receiving application.
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(parent = "flags", offset = 3, length = 1, format = "%b", display = "ack", description = "push current segment of data")
	public boolean flags_PSH() {
		return (flags() & FLAG_PSH) != 0;
	}

	/**
	 * Sets new value for the bit flag
	 * 
	 * @param value
	 *          sets the flag bit, false clears it
	 */
	public void flags_PSH(final boolean value) {
		setFlag(value, FLAG_PSH);
	}

	/**
	 * RST (1 bit) – Reset the connection
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(parent = "flags", offset = 2, length = 1, format = "%b", display = "ack", description = "reset connection")
	public boolean flags_RST() {
		return (flags() & FLAG_RST) != 0;
	}

	/**
	 * Sets new value for the bit flag
	 * 
	 * @param value
	 *          sets the flag bit, false clears it
	 */
	public void flags_RST(final boolean value) {
		setFlag(value, FLAG_RST);
	}

	/**
	 * SYN (1 bit) – Synchronize sequence numbers. Only the first packet sent from
	 * each end should have this flag set. Some other flags change meaning based
	 * on this flag, and some are only valid for when it is set, and others when
	 * it is clear.
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(parent = "flags", offset = 1, length = 1, format = "%b", display = "ack", description = "synchronize connection, startup")
	public boolean flags_SYN() {
		return (flags() & FLAG_SYN) != 0;
	}

	/**
	 * Sets new value for the bit flag
	 * 
	 * @param value
	 *          sets the flag bit, false clears it
	 */
	public void flags_SYN(final boolean value) {
		setFlag(value, FLAG_SYN);
	}

	/**
	 * URG (1 bit) – indicates that the Urgent pointer field is significant
	 * 
	 * @return true if bit flag is set, otherwise false
	 */
	@Field(parent = "flags", offset = 5, length = 1, format = "%b", display = "ack", description = "urgent, out-of-band data")
	public boolean flags_URG() {
		return (flags() & FLAG_URG) != 0;
	}

	/**
	 * Sets new value for the bit flag
	 * 
	 * @param value
	 *          sets the flag bit, false clears it
	 */
	public void flags_URG(final boolean value) {
		setFlag(value, FLAG_URG);
	}

	/**
	 * Returns a compact string representation of the flags contained within flags
	 * field
	 * 
	 * @return a terse representation of the flags
	 */
	public String flagsCompactString() {
		return Flag.toCompactString(flags());
	}

	/**
	 * Retruns a collection set representation of the flags contained within the
	 * flags field
	 * 
	 * @return a collection set of the flags field
	 */
	public Set<Flag> flagsEnum() {
		return Flag.asSet(flags());
	}

	/**
	 * Calculates the length of the TCP payload.
	 * 
	 * @return length of tcp segment data in bytes
	 */
	@Override
	public int getPayloadLength() {
		getPacket().getHeader(this.ip);
		return this.ip.length() - this.ip.hlen() * 4 - hlen() * 4;
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

	/**
	 * Data offset (4 bits). Specifies the size of the TCP header in 32-bit words.
	 * The minimum size header is 5 words and the maximum is 15 words thus giving
	 * the minimum size of 20 bytes and maximum of 60 bytes, allowing for up to 40
	 * bytes of options in the header. This field gets its name from the fact that
	 * it is also the offset from the start of the TCP segment to the actual data.
	 * 
	 * @return the field's value
	 */
	@Field(offset = 12 * BYTE, length = 4)
	public int hlen() {
		return (getUByte(12) & 0xF0) >> 4;
	}

	/**
	 * @param length
	 *          in 4 byte words
	 */
	public void hlen(final int length) {
		super.setUByte(12, ((getUByte(12) & 0x0F) | (length << 4)));
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

		return Checksum.pseudoTcp(this.packet, ipOffset, getOffset()) == 0;
	}

	/**
	 * Reserved (4 bits). For future use and should be set to zero.
	 * 
	 * @return the field's value
	 */
	@Field(offset = 12 * BYTE + 4, length = 4)
	public int reserved() {
		return getUByte(12) & 0x0F;
	}

	/**
	 * Sets a new value for the field.
	 * 
	 * @param value
	 *          new value (4 bits)
	 */
	public void reserved(final int value) {
		setUByte(12, value & 0x0F);
	}

	/**
	 * Sequence number (32 bits). Has a dual role:
	 * <ul>
	 * <li>If the SYN flag is set, then this is the initial sequence number. The
	 * sequence number of the actual first data byte (and the acknowledged number
	 * in the corresponding ACK) are then this sequence number plus 1.
	 * <li>If the SYN flag is clear, then this is the accumulated sequence number
	 * of the first data byte of this packet for the current session.
	 * </ul>
	 * 
	 * @return the field's value
	 */
	@Field(offset = 4 * BYTE, length = 16, format = "%x")
	public long seq() {
		return getUInt(4);
	}

	/**
	 * @param seq
	 */
	public void seq(final long seq) {
		super.setUInt(4, seq);
	}

	private void setFlag(final boolean state, final int flag) {
		if (state) {
			setFlag(flag);
		} else {
			clearFlag(flag);
		}
	}

	private void setFlag(final int flag) {
		super.setUByte(13, flags() | flag);
	}

	/**
	 * Source port (16 bits). Identifies the sending port.
	 * 
	 * @return the field's value
	 */
	@BindingVariable
	@Field(offset = 0, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int source() {
		return getUShort(0);
	}

	/**
	 * Sets a new value for the field (16 bits).
	 * 
	 * @param src
	 *          new value (16 bits)
	 */
	public void source(final int src) {
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

	/**
	 * Urgent pointer (16 bits). If the URG flag is set, then this 16-bit field is
	 * an offset from the sequence number indicating the last urgent data byte.
	 * 
	 * @return the field's value
	 */
	@Field(offset = 18 * BYTE, length = 16)
	public int urgent() {
		return getUShort(18);
	}

	/**
	 * @param urg
	 */
	public void urgent(final int urg) {
		super.setUShort(18, urg);
	}

	/**
	 * Window (16 bits). The size of the receive window, which specifies the
	 * number of bytes (beyond the sequence number in the acknowledgment field)
	 * that the receiver is currently willing to receive.
	 * <h2>Flow control</h2>
	 * TCP uses an end-to-end flow control protocol to avoid having the sender
	 * send data too fast for the TCP receiver to receive and process it reliably.
	 * Having a mechanism for flow control is essential in an environment where
	 * machines of diverse network speeds communicate. For example, if a PC sends
	 * data to a hand-held PDA that is slowly processing received data, the PDA
	 * must regulate data flow so as not to be overwhelmed.
	 * <p>
	 * TCP uses a sliding window flow control protocol. In each TCP segment, the
	 * receiver specifies in the receive window field the amount of additional
	 * received data (in bytes) that it is willing to buffer for the connection.
	 * The sending host can send only up to that amount of data before it must
	 * wait for an acknowledgment and window update from the receiving host.
	 * </p>
	 * <p>
	 * When a receiver advertises a window size of 0, the sender stops sending
	 * data and starts the persist timer. The persist timer is used to protect TCP
	 * from a deadlock situation that could arise if the window size update from
	 * the receiver is lost and the sender has no more data to send while the
	 * receiver is waiting for the new window size update. When the persist timer
	 * expires, the TCP sender sends a small packet so that the receiver sends an
	 * acknowledgement with the new window size.
	 * </p>
	 * <p>
	 * If a receiver is processing incoming data in small increments, it may
	 * repeatedly advertise a small receive window. This is referred to as the
	 * silly window syndrome, since it is inefficient to send only a few bytes of
	 * data in a TCP segment, given the relatively large overhead of the TCP
	 * header. TCP senders and receivers typically employ flow control logic to
	 * specifically avoid repeatedly sending small segments. The sender-side silly
	 * window syndrome avoidance logic is referred to as Nagle's algorithm.
	 * </p>
	 * <h2>Window scaling</h2>
	 * For more efficient use of high bandwidth networks, a larger TCP window size
	 * may be used. The TCP window size field controls the flow of data and its
	 * value is limited to between 2 and 65,535 bytes.
	 * <p>
	 * Since the size field cannot be expanded, a scaling factor is used. The TCP
	 * window scale option, as defined in RFC 1323, is an option used to increase
	 * the maximum window size from 65,535 bytes to 1 Gigabyte. Scaling up to
	 * larger window sizes is a part of what is necessary for TCP Tuning.
	 * </p>
	 * <p>
	 * The window scale option is used only during the TCP 3-way handshake. The
	 * window scale value represents the number of bits to left-shift the 16-bit
	 * window size field. The window scale value can be set from 0 (no shift) to
	 * 14 for each direction independently. Both sides must send the option in
	 * their SYN segments to enable window scaling in either direction.
	 * </p>
	 * <p>
	 * Some routers and packet firewalls rewrite the window scaling factor during
	 * a transmission. This causes sending and receiving sides to assume different
	 * TCP window sizes. The result is non-stable traffic that may be very slow.
	 * The problem is visible on some sending and receiving sites behind the path
	 * of defective routers.
	 * </p>
	 * 
	 * @return the field's value
	 */
	@Field(offset = 14 * BYTE, length = 16)
	public int window() {
		return getUShort(14);
	}

	/**
	 * Sets the window field to new value.
	 * 
	 * @param value
	 *          new value for the field
	 */
	public void window(final int value) {
		super.setUShort(14, value);
	}

	/**
	 * A scaled, window field value. The size of the receive window, which
	 * specifies the number of bytes (beyond the sequence number in the
	 * acknowledgment field) that the receiver is currently willing to receive.
	 * <p>
	 * This getter method, takes into account window scaling, as described below,
	 * and applies the scaling factor and returning the value.
	 * </p>
	 * <h2>Window scaling</h2>
	 * For more efficient use of high bandwidth networks, a larger TCP window size
	 * may be used. The TCP window size field controls the flow of data and its
	 * value is limited to between 2 and 65,535 bytes.
	 * <p>
	 * Since the size field cannot be expanded, a scaling factor is used. The TCP
	 * window scale option, as defined in RFC 1323, is an option used to increase
	 * the maximum window size from 65,535 bytes to 1 Gigabyte. Scaling up to
	 * larger window sizes is a part of what is necessary for TCP Tuning.
	 * </p>
	 * <p>
	 * The window scale option is used only during the TCP 3-way handshake. The
	 * window scale value represents the number of bits to left-shift the 16-bit
	 * window size field. The window scale value can be set from 0 (no shift) to
	 * 14 for each direction independently. Both sides must send the option in
	 * their SYN segments to enable window scaling in either direction.
	 * </p>
	 * <p>
	 * Some routers and packet firewalls rewrite the window scaling factor during
	 * a transmission. This causes sending and receiving sides to assume different
	 * TCP window sizes. The result is non-stable traffic that may be very slow.
	 * The problem is visible on some sending and receiving sites behind the path
	 * of defective routers.
	 * </p>
	 * 
	 * @return the scaled value of the window field
	 */
	public int windowScaled() {
		return window() << 6;
	}
}
