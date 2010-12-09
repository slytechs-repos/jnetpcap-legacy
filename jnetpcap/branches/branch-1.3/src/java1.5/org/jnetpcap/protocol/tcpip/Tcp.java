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
package org.jnetpcap.protocol.tcpip;

import java.util.EnumSet;
import java.util.Set;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeaderChecksum;
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.BindingVariable;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.util.checksum.Checksum;

// TODO: Auto-generated Javadoc
/**
 * The Class Tcp.
 */
@Header
@SuppressWarnings("unused")
public class Tcp
    extends
    JHeaderMap<Tcp> implements JHeaderChecksum {

	/**
	 * The Class AlternateChecksum.
	 */
	@Header(id = 15)
	public static class AlternateChecksum
	    extends
	    TcpOption {

		/**
		 * Data.
		 * 
		 * @return the byte[]
		 */
		@Field(offset = 2 * BYTE, format = "#hexdump#")
		public byte[] data() {
			return getByteArray(2, dataLength() / 8); // Allocates a new array
		}

		/**
		 * Data to array.
		 * 
		 * @param array
		 *          the array
		 * @return the byte[]
		 */
		public byte[] dataToArray(byte[] array) {
			return getByteArray(2, array);
		}

		/**
		 * Data length.
		 * 
		 * @return the int
		 */
		@Dynamic(Field.Property.LENGTH)
		public int dataLength() {
			return (length() - 2) * BYTE; // In bits
		}
	}

	/**
	 * The Class AlternateChecksumRequest.
	 */
	@Header(id = 14)
	public static class AlternateChecksumRequest
	    extends
	    TcpOption {

		/**
		 * The Enum Algorithm.
		 */
		public enum Algorithm {
			
			/** The TC p_ checksum. */
			TCP_CHECKSUM(0),

			/** The FLETCHE r_8 bit. */
			FLETCHER_8BIT(1),
			
			/** The FLETCHE r_16 bit. */
			FLETCHER_16BIT(2),

			/** The AVOIDANCE. */
			AVOIDANCE(3);

			/** The type. */
			public final int type;

			/**
			 * Instantiates a new algorithm.
			 * 
			 * @param type
			 *          the type
			 */
			private Algorithm(int type) {
				this.type = type;
			}

			/**
			 * Value of.
			 * 
			 * @param type
			 *          the type
			 * @return the algorithm
			 */
			public static Algorithm valueOf(int type) {
				for (Algorithm a : values()) {
					if (type == a.type) {
						return a;
					}
				}

				return null;
			}
		}

		/**
		 * Algorithm.
		 * 
		 * @return the int
		 */
		@Field(offset = 2 * BYTE, length = 1 * BYTE)
		public int algorithm() {
			return getUByte(2);
		}

		/**
		 * Algorithm enum.
		 * 
		 * @return the algorithm
		 */
		public Algorithm algorithmEnum() {
			return Algorithm.valueOf(algorithm());
		}

		/**
		 * Algorithm.
		 * 
		 * @param value
		 *          the value
		 */
		public void algorithm(int value) {
			setUByte(2, value);
		}
	}

	/**
	 * The Enum Flag.
	 */
	public enum Flag {
		
		/** The ACK. */
		ACK,
		
		/** The CWR. */
		CWR,
		
		/** The ECE. */
		ECE,
		
		/** The FIN. */
		FIN,
		
		/** The PSH. */
		PSH,
		
		/** The RST. */
		RST,
		
		/** The SYN. */
		SYN,
		
		/** The URG. */
		URG, ;

		/**
		 * As set.
		 * 
		 * @param flags
		 *          the flags
		 * @return the sets the
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
		 * To compact string.
		 * 
		 * @param flags
		 *          the flags
		 * @return the string
		 */
		public static String toCompactString(final int flags) {
			return toCompactString(asSet(flags));
		}

		/**
		 * To compact string.
		 * 
		 * @param flags
		 *          the flags
		 * @return the string
		 */
		public static String toCompactString(final Set<Flag> flags) {
			final StringBuilder b = new StringBuilder(values().length);
			for (final Flag f : flags) {
				b.append(f.name().charAt(0));
			}

			return b.toString();
		}
	}

	/**
	 * The Class MSS.
	 */
	@Header(id = 2, description = "Maximum Segment Size")
	public static class MSS
	    extends
	    TcpOption {

		/**
		 * Mss.
		 * 
		 * @return the int
		 */
		@Field(offset = 2 * BYTE, length = 2 * BYTE)
		public int mss() {
			return getUShort(2);
		}

		/**
		 * Mss.
		 * 
		 * @param value
		 *          the value
		 */
		public void mss(int value) {
			setUShort(2, value);
		}
	}

	/**
	 * The Class NoOp.
	 */
	@Header(id = 1)
	public static class NoOp
	    extends
	    TcpOption {
	}

	/**
	 * The Class SACK.
	 */
	@Header(id = 5)
	public static class SACK
	    extends
	    TcpOption {

		/**
		 * Block count.
		 * 
		 * @return the int
		 */
		public int blockCount() {
			return (size() - 2) / 8; // (block_size) div 64-bit-block-length
		}

		/**
		 * Blocks length.
		 * 
		 * @return the int
		 */
		@Dynamic(Field.Property.LENGTH)
		public int blocksLength() {
			return blockCount() * 64; // In bits
		}

		/**
		 * Blocks.
		 * 
		 * @return the long[]
		 */
		@Field(offset = 2 * BYTE)
		public long[] blocks() {
			return blocksToArray(new long[blockCount() * 2]);
		}

		/**
		 * Blocks.
		 * 
		 * @param array
		 *          the array
		 */
		public void blocks(long[] array) {
			final int count = array.length / 2;

			for (int i = 0; i < count; i++) {
				setUInt(i * 4 + 2, array[i]);
			}

			/*
			 * Updata the option length field
			 */
			length(array.length * 4 + 2);
		}

		/**
		 * Blocks to array.
		 * 
		 * @param array
		 *          the array
		 * @return the long[]
		 */
		public long[] blocksToArray(long[] array) {
			final int count =
			    (array.length < blockCount() * 2) ? array.length : blockCount() * 2;

			for (int i = 0; i < count; i++) {
				array[i] = getUInt(i * 4 + 2);
			}

			return array;
		}
	}

	/**
	 * The Class SACK_PERMITTED.
	 */
	@Header(id = 4)
	public static class SACK_PERMITTED
	    extends
	    TcpOption {
	}

	/**
	 * The Class TcpOption.
	 */
	public static abstract class TcpOption
	    extends
	    JSubHeader<Tcp> {

		/**
		 * The Enum OptionCode.
		 */
		public enum OptionCode {

			/** The ALTERNAT e_ checksum. */
			ALTERNATE_CHECKSUM(15),
			
			/** The ALTERNAT e_ checksu m_ request. */
			ALTERNATE_CHECKSUM_REQUEST(14),
			
			/** The EN d_ o f_ optio n_ list. */
			END_OF_OPTION_LIST(0),
			
			/** The MAXIMU m_ segmen t_ size. */
			MAXIMUM_SEGMENT_SIZE(2),
			
			/** The N o_ op. */
			NO_OP(1),
			
			/** The SACK. */
			SACK(5),
			
			/** The SAC k_ permitted. */
			SACK_PERMITTED(4),
			
			/** The TIMESTAP. */
			TIMESTAP(8),
			
			/** The WINDO w_ scale. */
			WINDOW_SCALE(3)

			;
			
			/**
			 * Value of.
			 * 
			 * @param id
			 *          the id
			 * @return the option code
			 */
			public static OptionCode valueOf(int id) {
				for (OptionCode c : values()) {
					if (c.id == id) {
						return c;
					}
				}

				return null;
			}

			/** The id. */
			public final int id;

			/**
			 * Instantiates a new option code.
			 * 
			 * @param id
			 *          the id
			 */
			private OptionCode(int id) {
				this.id = id;
			}

		}

		/**
		 * Code.
		 * 
		 * @return the int
		 */
		@Field(offset = 0 * BYTE, length = 1 * BYTE)
		public int code() {
			return getUByte(0);
		}

		/**
		 * Code.
		 * 
		 * @param value
		 *          the value
		 */
		public void code(int value) {
			setUByte(0, value);
		}

		/**
		 * Length.
		 * 
		 * @return the int
		 */
		@Field(offset = 1 * BYTE, length = 1 * BYTE)
		public int length() {
			return lengthCheck(null) ? getUByte(1) : 1;
		}

		/**
		 * Length description.
		 * 
		 * @return the string
		 */
		@Dynamic(Field.Property.DESCRIPTION)
		public String lengthDescription() {
			return lengthCheck(null) ? null : "implied length from option type";
		}

		/**
		 * Length.
		 * 
		 * @param value
		 *          the value
		 */
		public void length(int value) {
			setUByte(1, value);
		}

		/**
		 * Length check.
		 * 
		 * @param name
		 *          the name
		 * @return true, if successful
		 */
		@Dynamic(field = "length", value = Field.Property.CHECK)
		public boolean lengthCheck(String name) {
			return (code() > 1); // Only 0 and 1 don't have length field
		}
	}

	/**
	 * The Class Timestamp.
	 */
	@Header(id = 8)
	public static class Timestamp
	    extends
	    TcpOption {

		/**
		 * Tsecr.
		 * 
		 * @return the long
		 */
		@Field(offset = 6 * BYTE, length = 4 * BYTE)
		public long tsecr() {
			return getUInt(6);
		}

		/**
		 * Tsecr.
		 * 
		 * @param value
		 *          the value
		 */
		public void tsecr(long value) {
			setUInt(6, value);
		}

		/**
		 * Tsval.
		 * 
		 * @return the long
		 */
		@Field(offset = 2 * BYTE, length = 4 * BYTE)
		public long tsval() {
			return getUInt(2);
		}

		/**
		 * Tsval.
		 * 
		 * @param value
		 *          the value
		 */
		public void tsval(long value) {
			setUInt(2, value);
		}
	}

	/**
	 * The Class WindowScale.
	 */
	@Header(id = 3)
	public static class WindowScale
	    extends
	    TcpOption {

		/**
		 * Scale.
		 * 
		 * @return the int
		 */
		@Field(offset = 2 * BYTE, length = 1 * BYTE)
		public int scale() {
			return getUByte(2);
		}

		/**
		 * Scale.
		 * 
		 * @param value
		 *          the value
		 */
		public void scale(int value) {
			setUByte(2, value);
		}
	}

	/** The Constant FLAG_ACK. */
	private static final int FLAG_ACK = 0x10;

	/** The Constant FLAG_CONG. */
	private static final int FLAG_CONG = 0x80;

	/** The Constant FLAG_CWR. */
	private static final int FLAG_CWR = 0x80;

	/** The Constant FLAG_ECE. */
	private static final int FLAG_ECE = 0x40;

	/** The Constant FLAG_ECN. */
	private static final int FLAG_ECN = 0x40;

	/** The Constant FLAG_FIN. */
	private static final int FLAG_FIN = 0x01;

	/** The Constant FLAG_PSH. */
	private static final int FLAG_PSH = 0x08;

	/** The Constant FLAG_RST. */
	private static final int FLAG_RST = 0x04;

	/** The Constant FLAG_SYN. */
	private static final int FLAG_SYN = 0x02;

	/** The Constant FLAG_URG. */
	private static final int FLAG_URG = 0x20;

	/** The Constant ID. */
	public static final int ID = JProtocol.TCP_ID;

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
		final int hlen = (buffer.getUByte(offset + 12) & 0xF0) >> 4;
		return hlen * 4;
	}

	/** The bi directional hashcode. */
	private int biDirectionalHashcode;

	/** The ip. */
	private final Ip4 ip = new Ip4();

	/** The uni directional hashcode. */
	private int uniDirectionalHashcode;

	/**
	 * Ack.
	 * 
	 * @return the long
	 */
	@Field(offset = 8 * BYTE, length = 16, format = "%x")
	public long ack() {
		return getUInt(8);
	}

	/**
	 * Ack.
	 * 
	 * @param ack
	 *          the ack
	 */
	public void ack(final long ack) {
		super.setUInt(8, ack);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderChecksum#calculateChecksum()
	 */
	public int calculateChecksum() {

		if (getIndex() == -1) {
			throw new IllegalStateException("Oops index not set");
		}

		final int ipOffset = getPreviousHeaderOffset();

		return Checksum.inChecksumShouldBe(checksum(), Checksum.pseudoTcp(
		    this.packet, ipOffset, getOffset()));
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderChecksum#checksum()
	 */
	@Field(offset = 16 * BYTE, length = 16, format = "%x")
	public int checksum() {
		return getUShort(16);
	}

	/**
	 * Checksum.
	 * 
	 * @param crc
	 *          the crc
	 */
	public void checksum(final int crc) {
		super.setUShort(16, crc);
	}

	/**
	 * Checksum description.
	 * 
	 * @return the string
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

	/**
	 * Clear flag.
	 * 
	 * @param flag
	 *          the flag
	 */
	private void clearFlag(int flag) {
		super.setUByte(13, flags() & ~flag);

	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeader#decodeHeader()
	 */
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

		optionsBitmap = 0;

		// System.out.printf("offset=%d, %s %s", getOffset(), getPacket().getState()
		// .toDebugString(), toHexdump());
		final int hlen = hlen() * 4;

		for (int i = 20; i < hlen; i++) {
			final int id = getUByte(i);
			optionsOffsets[id] = i;
			optionsBitmap |= (1 << id);

			final TcpOption.OptionCode code = TcpOption.OptionCode.valueOf(id);
			if (code == null) {
				break; // We are done, something seriously wrong with the header
			}

//			System.out.printf("%s: i=%d id=%d ", code, i, id);
			switch (code) {
				case NO_OP:
					optionsLength[id] = 1;
					break;

				case END_OF_OPTION_LIST:
					optionsLength[id] = hlen - i;
					i = hlen;
					break;

				default:
					final int length = getUByte(i + 1); // Length option field
//				System.out.printf("length=%d", length);
					i += length -1;
					optionsLength[id] = length;
					break;
			}

//			System.out.println();
			// System.out.printf("i=%d id=%d bitmap=0x%X length=%d\n", i, id,
			// optionsBitmap, optionsLength[id]);
		}

	}

	/**
	 * Destination.
	 * 
	 * @return the int
	 */
	@BindingVariable
	@Field(offset = 16, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int destination() {
		return getUShort(2);
	}

	/**
	 * Destination.
	 * 
	 * @param value
	 *          the value
	 */
	public void destination(final int value) {
		super.setUShort(2, value);
	}

	/**
	 * Flags.
	 * 
	 * @return the int
	 */
	@Field(offset = 13 * BYTE, length = 8, format = "%x")
	public int flags() {
		return getUByte(13);
	}

	/**
	 * Flags.
	 * 
	 * @param value
	 *          the value
	 */
	public void flags(final int value) {
		super.setUByte(13, value);
	}

	/**
	 * Flags_ ack.
	 * 
	 * @return true, if successful
	 */
	@Field(parent = "flags", offset = 4, length = 1, format = "%b", display = "ack", description = "acknowledgment")
	public boolean flags_ACK() {
		return (flags() & FLAG_ACK) != 0;
	}

	/**
	 * Flags_ ack.
	 * 
	 * @param value
	 *          the value
	 */
	public void flags_ACK(final boolean value) {
		setFlag(value, FLAG_ACK);
	}

	/**
	 * Flags_ cwr.
	 * 
	 * @return true, if successful
	 */
	@Field(parent = "flags", offset = 7, length = 1, format = "%b", display = "cwr", description = "reduced (cwr)")
	public boolean flags_CWR() {
		return (flags() & FLAG_CWR) != 0;
	}

	/**
	 * Flags_ cwr.
	 * 
	 * @param value
	 *          the value
	 */
	public void flags_CWR(final boolean value) {
		setFlag(value, FLAG_CWR);
	}

	/**
	 * Flags_ ece.
	 * 
	 * @return true, if successful
	 */
	@Field(parent = "flags", offset = 6, length = 1, format = "%b", display = "ece", description = "ECN echo flag")
	public boolean flags_ECE() {
		return (flags() & FLAG_ECE) != 0;
	}

	/**
	 * Flags_ ece.
	 * 
	 * @param value
	 *          the value
	 */
	public void flags_ECE(final boolean value) {
		setFlag(value, FLAG_ECE);
	}

	/**
	 * Flags_ fin.
	 * 
	 * @return true, if successful
	 */
	@Field(parent = "flags", offset = 0, length = 1, format = "%b", display = "fin", description = "closing down connection")
	public boolean flags_FIN() {
		return (flags() & FLAG_FIN) != 0;
	}

	/**
	 * Flags_ fin.
	 * 
	 * @param value
	 *          the value
	 */
	public void flags_FIN(final boolean value) {
		setFlag(value, FLAG_FIN);
	}

	/**
	 * Flags_ psh.
	 * 
	 * @return true, if successful
	 */
	@Field(parent = "flags", offset = 3, length = 1, format = "%b", display = "ack", description = "push current segment of data")
	public boolean flags_PSH() {
		return (flags() & FLAG_PSH) != 0;
	}

	/**
	 * Flags_ psh.
	 * 
	 * @param value
	 *          the value
	 */
	public void flags_PSH(final boolean value) {
		setFlag(value, FLAG_PSH);
	}

	/**
	 * Flags_ rst.
	 * 
	 * @return true, if successful
	 */
	@Field(parent = "flags", offset = 2, length = 1, format = "%b", display = "ack", description = "reset connection")
	public boolean flags_RST() {
		return (flags() & FLAG_RST) != 0;
	}

	/**
	 * Flags_ rst.
	 * 
	 * @param value
	 *          the value
	 */
	public void flags_RST(final boolean value) {
		setFlag(value, FLAG_RST);
	}

	/**
	 * Flags_ syn.
	 * 
	 * @return true, if successful
	 */
	@Field(parent = "flags", offset = 1, length = 1, format = "%b", display = "ack", description = "synchronize connection, startup")
	public boolean flags_SYN() {
		return (flags() & FLAG_SYN) != 0;
	}

	/**
	 * Flags_ syn.
	 * 
	 * @param value
	 *          the value
	 */
	public void flags_SYN(final boolean value) {
		setFlag(value, FLAG_SYN);
	}

	/**
	 * Flags_ urg.
	 * 
	 * @return true, if successful
	 */
	@Field(parent = "flags", offset = 5, length = 1, format = "%b", display = "ack", description = "urgent, out-of-band data")
	public boolean flags_URG() {
		return (flags() & FLAG_URG) != 0;
	}

	/**
	 * Flags_ urg.
	 * 
	 * @param value
	 *          the value
	 */
	public void flags_URG(final boolean value) {
		setFlag(value, FLAG_URG);
	}

	/**
	 * Flags compact string.
	 * 
	 * @return the string
	 */
	public String flagsCompactString() {
		return Flag.toCompactString(flags());
	}

	/**
	 * Flags enum.
	 * 
	 * @return the sets the
	 */
	public Set<Flag> flagsEnum() {
		return Flag.asSet(flags());
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeader#getPayloadLength()
	 */
	@Override
	public int getPayloadLength() {
		getPacket().getHeader(this.ip);
		return this.ip.length() - this.ip.hlen() * 4 - hlen() * 4;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return this.biDirectionalHashcode;
	}

	/**
	 * Hlen.
	 * 
	 * @return the int
	 */
	@Field(offset = 12 * BYTE, length = 4)
	public int hlen() {
		return (getUByte(12) & 0xF0) >> 4;
	}

	/**
	 * Hlen.
	 * 
	 * @param length
	 *          the length
	 */
	public void hlen(final int length) {
		super.setUByte(12, ((getUByte(12) & 0x0F) | (length << 4)));
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JHeaderChecksum#isChecksumValid()
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
	 * Reserved.
	 * 
	 * @return the int
	 */
	@Field(offset = 12 * BYTE + 4, length = 4)
	public int reserved() {
		return getUByte(12) & 0x0F;
	}

	/**
	 * Reserved.
	 * 
	 * @param value
	 *          the value
	 */
	public void reserved(final int value) {
		setUByte(12, value & 0x0F);
	}

	/**
	 * Seq.
	 * 
	 * @return the long
	 */
	@Field(offset = 4 * BYTE, length = 16, format = "%x")
	public long seq() {
		return getUInt(4);
	}

	/**
	 * Seq.
	 * 
	 * @param seq
	 *          the seq
	 */
	public void seq(final long seq) {
		super.setUInt(4, seq);
	}

	/**
	 * Sets the flag.
	 * 
	 * @param state
	 *          the state
	 * @param flag
	 *          the flag
	 */
	private void setFlag(final boolean state, final int flag) {
		if (state) {
			setFlag(flag);
		} else {
			clearFlag(flag);
		}
	}

	/**
	 * Sets the flag.
	 * 
	 * @param flag
	 *          the new flag
	 */
	private void setFlag(final int flag) {
		super.setUByte(13, flags() | flag);
	}

	/**
	 * Source.
	 * 
	 * @return the int
	 */
	@BindingVariable
	@Field(offset = 0, length = 16)
	@FlowKey(index = 2, reversable = true)
	public int source() {
		return getUShort(0);
	}

	/**
	 * Source.
	 * 
	 * @param src
	 *          the src
	 */
	public void source(final int src) {
		super.setUShort(0, src);
	}

	/**
	 * Uni hash code.
	 * 
	 * @return the int
	 */
	public int uniHashCode() {
		return this.uniDirectionalHashcode;
	}

	/**
	 * Urgent.
	 * 
	 * @return the int
	 */
	@Field(offset = 18 * BYTE, length = 16)
	public int urgent() {
		return getUShort(18);
	}

	/**
	 * Urgent.
	 * 
	 * @param urg
	 *          the urg
	 */
	public void urgent(final int urg) {
		super.setUShort(18, urg);
	}

	/**
	 * Window.
	 * 
	 * @return the int
	 */
	@Field(offset = 14 * BYTE, length = 16)
	public int window() {
		return getUShort(14);
	}

	/**
	 * Window.
	 * 
	 * @param value
	 *          the value
	 */
	public void window(final int value) {
		super.setUShort(14, value);
	}

	/**
	 * Window scaled.
	 * 
	 * @return the int
	 */
	public int windowScaled() {
		return window() << 6;
	}
}
