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
package org.jnetpcap.protocol.voip;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Class Rtp.
 */
@Header(spec = Rtp.RFC, suite = ProtocolSuite.VOIP, description = Rtp.DESCRIPTION)
public class Rtp
    extends
    JHeader {

	/**
	 * The Class Extension.
	 */
	public abstract static class Extension
	    extends
	    JSubHeader<Rtp> {

		/** The Constant STATIC_HEADER_LENGTH. */
		public final static int STATIC_HEADER_LENGTH = 4;

		/**
		 * Header length.
		 * 
		 * @param buffer
		 *          the buffer
		 * @param offset
		 *          the offset
		 * @return the int
		 */
		@HeaderLength
		public static int headerLength(final JBuffer buffer, final int offset) {
			return (buffer.getUShort(2) * 4) + STATIC_HEADER_LENGTH;
		}

		/**
		 * Length.
		 * 
		 * @return the int
		 */
		@Field(offset = 2 * BYTE, length = 16)
		public int length() {
			return super.getUShort(2);
		}

		/**
		 * Profile specific.
		 * 
		 * @return the int
		 */
		public int profileSpecific() {
			return super.getUShort(0);
		}
	}

	/**
	 * The Enum PayloadType.
	 */
	public enum PayloadType {
		
		/** The CN. */
		CN,
		
		/** The DV i4_16 k. */
		DVI4_16K,

		/** The DV i4_8 k. */
		DVI4_8K,

		/** The G711. */
		G711,

		/** The G721. */
		G721,

		/** The G722. */
		G722,

		/** The G723. */
		G723,

		/** The G728. */
		G728,

		/** The GSM. */
		GSM,

		/** The L16_1 ch. */
		L16_1CH,

		/** The L16_2 ch. */
		L16_2CH,

		/** The LPC. */
		LPC,

		/** The MPA. */
		MPA,

		/** The PCMA. */
		PCMA,

		/** The QCELP. */
		QCELP,

		/** The RESERVE d1. */
		RESERVED1,

		/** The RESERVE d2. */
		RESERVED2;

		/**
		 * Value of.
		 * 
		 * @param type
		 *          the type
		 * @return the payload type
		 */
		public static PayloadType valueOf(final int type) {
			return values()[type];
		}
	}

	/** The Constant CC_MASK. */
	public final static int CC_MASK = 0x0F;

	/** The Constant CC_OFFSET. */
	public final static int CC_OFFSET = 0;

	/** The Constant CSRC_LENGTH. */
	public final static int CSRC_LENGTH = 4;

	/** The Constant DESCRIPTION. */
	public final static String DESCRIPTION = "real-time transfer protocol";

	/** The Constant EXTENSION_MASK. */
	public final static int EXTENSION_MASK = 0x10;

	/** The Constant EXTENSION_OFFSET. */
	public final static int EXTENSION_OFFSET = 4;

	/** The ID. */
	public static int ID = JProtocol.RTP_ID;

	/** The Constant MARKER_MASK. */
	public final static int MARKER_MASK = 0x80;

	/** The Constant MARKER_OFFSET. */
	public final static int MARKER_OFFSET = 7;

	/** The Constant PADDING_MASK. */
	public final static int PADDING_MASK = 0x20;

	/** The Constant PADDING_OFFSET. */
	public final static int PADDING_OFFSET = 5;

	/** The Constant RFC. */
	public final static String RFC = "rfc3550";

	/** The Constant RTP_UDP_PORT. */
	public final static int RTP_UDP_PORT = 5004;

	/** The Constant STATIC_HEADER_LENGTH. */
	public final static int STATIC_HEADER_LENGTH = 12;

	/** The Constant SUITE. */
	public final static ProtocolSuite SUITE = ProtocolSuite.VOIP;

	/** The Constant TYPE_MASK. */
	public final static int TYPE_MASK = 0x7F;

	/** The Constant TYPE_OFFSET. */
	public final static int TYPE_OFFSET = 0;

	/** The Constant VERSION_MASK. */
	public final static int VERSION_MASK = 0xC0;

	/** The Constant VERSION_OFFSET. */
	public final static int VERSION_OFFSET = 6;

	/**
	 * Base header length.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	private static int baseHeaderLength(final JBuffer buffer, final int offset) {
		final byte b0 = buffer.getByte(offset);
		final int cc = (b0 & CC_MASK) >> CC_OFFSET;

		return Rtp.STATIC_HEADER_LENGTH + (cc * CSRC_LENGTH);
	}

	/**
	 * Header length.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */

	@HeaderLength
	public static int headerLength(final JBuffer buffer, final int offset) {
		final int rtpBaseHeader = baseHeaderLength(buffer, offset);

		if ((buffer.getByte(offset) & EXTENSION_MASK) > 0) {
			return rtpBaseHeader
			    + Rtp.Extension.headerLength(buffer, offset + rtpBaseHeader);
		} else {
			return rtpBaseHeader;
		}
	}

	/**
	 * Postfix length.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	@HeaderLength(HeaderLength.Type.POSTFIX)
	public static int postfixLength(final JBuffer buffer, final int offset) {
		if ((buffer.getByte(offset) & PADDING_MASK) > 0) {
			return buffer.getUByte(buffer.size() - 1);
		} else {
			return 5;
		}
	}

	/**
	 * Count.
	 * 
	 * @return the int
	 */
	@Field(offset = 4, length = 4)
	public int count() {
		return (super.getByte(0) & CC_MASK) >> CC_OFFSET;
	}

	/**
	 * Csrc.
	 * 
	 * @return the int[]
	 */
	@Field(offset = STATIC_HEADER_LENGTH * BYTE)
	public int[] csrc() {
		final int count = count();

		final int[] csrc = new int[count];

		for (int i = 0; i < csrc.length; i++) {
			csrc[i] = super.getInt(STATIC_HEADER_LENGTH + i * CSRC_LENGTH);
		}

		return csrc;
	}

	/**
	 * Csrc length.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	public int csrcLength() {
		return count() * CSRC_LENGTH * BYTE;
	}

	/**
	 * Checks for extension.
	 * 
	 * @return true, if successful
	 */
	@Field(offset = 3, length = 1)
	public boolean hasExtension() {
		return ((super.getByte(0) & EXTENSION_MASK) >> EXTENSION_OFFSET) > 0;
	}

	/**
	 * Checks for marker.
	 * 
	 * @return true, if successful
	 */
	@Field(offset = 8, length = 1)
	public boolean hasMarker() {
		return ((super.getByte(1) & MARKER_MASK) >> MARKER_OFFSET) > 0;
	}

	/**
	 * Checks for padding.
	 * 
	 * @return true, if successful
	 */
	@Field(offset = 2, length = 1)
	public boolean hasPadding() {
		return ((super.getByte(0) & PADDING_MASK) >> PADDING_OFFSET) > 0;
	}

	/**
	 * Padding length.
	 * 
	 * @return the int
	 */
	public int paddingLength() {
		if (hasPostfix() == false) {
			return 0;
		}

		final int length =
		    this.packet.getUByte(getPostfixOffset() + getPostfixLength() - 1);

		return length;
	}

	/**
	 * Sequence.
	 * 
	 * @return the int
	 */
	@Field(offset = 16, length = 16)
	public int sequence() {
		return super.getUShort(2);
	}

	/**
	 * Ssrc.
	 * 
	 * @return the long
	 */
	@Field(offset = 8 * BYTE, length = 32)
	public long ssrc() {
		return super.getUInt(8);
	}

	/**
	 * Timestamp.
	 * 
	 * @return the long
	 */
	@Field(offset = 4 * BYTE, length = 32)
	public long timestamp() {
		return super.getUInt(4);
	}

	/**
	 * Type.
	 * 
	 * @return the int
	 */
	@Field(offset = 9, length = 7)
	public int type() {
		return (super.getByte(1) & TYPE_MASK) >> TYPE_OFFSET;
	}

	/**
	 * Type enum.
	 * 
	 * @return the payload type
	 */
	public PayloadType typeEnum() {
		return PayloadType.valueOf(type());
	}

	/**
	 * Version.
	 * 
	 * @return the int
	 */
	@Field(offset = 0, length = 2)
	public int version() {
		return (super.getByte(0) & VERSION_MASK) >> VERSION_OFFSET;
	}

	/**
	 * Gets the Rtp packet's payload.
	 * 
	 * @return buffer containing payload that is right after this Rtp header
	 */
	// public byte[] payload() {
	// return packet.getByteArray(getPayloadOffset(), getPayloadLength());
	// }
}
