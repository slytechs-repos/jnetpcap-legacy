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
package org.jnetpcap.packet.header;

import java.util.EnumSet;
import java.util.Set;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JHeaderType;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.BindingVariable;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldSetter;
import org.jnetpcap.packet.annotate.FlowKey;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.BindingVariable.MatchType;
import org.jnetpcap.packet.annotate.Header.Layer;

/**
 * IP version 4. Network layer internet protocol version 4.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(name = "Ip4", nicname = "Ip", osi = Layer.NETWORK, spec = "RFC792", description = "ip version 4")
public class Ip4
    extends JHeaderMap<Ip4> {

	/**
	 * A table of IpTypes and their names
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Ip4Type implements JHeaderType {
		/**
		 * Internet control messaging protocol
		 */
		ICMP("icmp", 1),

		/**
		 * Ttransmission control protocol
		 */
		TCP("tcp", 6),

		/**
		 * Unreliable datagram protocol
		 */
		UDP("udp", 17), ;
		/**
		 * Name of the constant
		 * 
		 * @param type
		 *          ip type number
		 * @return constants name
		 */
		public static String toString(int type) {
			for (Ip4Type t : values()) {
				for (int i : t.typeValues) {
					if (i == type) {
						return t.description;
					}
				}
			}

			return Integer.toString(type);
		}

		/**
		 * Converts a numerical type to constant
		 * 
		 * @param type
		 *          Ip4 type number
		 * @return constant or null if not found
		 */
		public static Ip4Type valueOf(int type) {
			for (Ip4Type t : values()) {
				for (int i : t.typeValues) {
					if (i == type) {
						return t;
					}
				}
			}

			return null;
		}

		private final String description;

		private final int[] typeValues;

		private Ip4Type(int... typeValues) {
			this.typeValues = typeValues;
			this.description = name().toLowerCase();
		}

		private Ip4Type(String description, int... typeValues) {
			this.typeValues = typeValues;
			this.description = description;

		}

		/**
		 * Description of the type value
		 * 
		 * @return description string
		 */
		public final String getDescription() {
			return this.description;
		}

		/**
		 * Converts contant to numerical ip type
		 * 
		 * @return Ip4 type number
		 */
		public final int[] getTypeValues() {
			return this.typeValues;
		}
	}

	/**
	 * Baseclass for all Ip option headers
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static abstract class IpOption
	    extends JSubHeader<Ip4> {

		/**
		 * A table of IpOption types and their names
		 * 
		 * @author Mark Bednarczyk
		 * @author Sly Technologies, Inc.
		 */
		public enum OptionCode {
			/* 0 */
			END_OF_OPTION_LIST(0),
			/* 3 */
			LOOSE_SOURCE_ROUTE(3),
			/* 1 */
			NO_OP(1),
			/* 7 */
			RECORD_ROUTE(7),
			/* 2 */
			SECURITY(2),
			/* 8 */
			STREAM_ID(8),
			/* 9 */
			STRICT_SOURCE_ROUTE(9),
			/* 4 */
			TIMESTAMP(4),
			/* 5 */
			UNASSIGNED1(5),
			/* 6 */
			UNASSIGNED2(6), ;
			public final int id;

			private OptionCode(int id) {
				this.id = id;
			}

			public static OptionCode valueOf(int id) {
				for (OptionCode c : values()) {
					if (c.id == id) {
						return c;
					}
				}

				return null;
			}
		}

		@HeaderLength
		public static int headerLength(JBuffer buffer, int offset) {
			return buffer.getUByte(1);
		}

		/**
		 * Gets the Ip4.code field. Specifies the optional header type.
		 * <h3>Header Spec</h3>
		 * <table border=1>
		 * <tr>
		 * <td> Protocol Header:</td>
		 * <td> Ip4</td>
		 * </tr>
		 * <tr>
		 * <td> Protocol Family:</td>
		 * <td> Networking</td>
		 * </tr>
		 * <tr>
		 * <td> OSI Layer:</td>
		 * <td> 3</td>
		 * </tr>
		 * <tr>
		 * <td> Field Property:</td>
		 * <td> constant offset</td>
		 * </tr>
		 * <tr>
		 * <td> Field Offset:</td>
		 * <td> getUByte(0) & 0x1F</td>
		 * </tr>
		 * </table>
		 * <h3>Header Diagram</h3>
		 * 
		 * <pre>
		 * +------+-----------------+
		 * | CODE | optional header |
		 * +------+-----------------+
		 * </pre>
		 * 
		 * @return code field value
		 */
		@Field(offset = 0, length = 3, format = "%d")
		public int code() {
			return getUByte(0) & 0x1F;
		}

		/**
		 * Sets the Ip4.code field. Specifies the optional header type.
		 * <h3>Header Spec</h3>
		 * <table border=1>
		 * <tr>
		 * <td> Protocol Header:</td>
		 * <td> Ip4</td>
		 * </tr>
		 * <tr>
		 * <td> Protocol Family:</td>
		 * <td> Networking</td>
		 * </tr>
		 * <tr>
		 * <td> OSI Layer:</td>
		 * <td> 3</td>
		 * </tr>
		 * <tr>
		 * <td> Field Property:</td>
		 * <td> constant offset</td>
		 * </tr>
		 * <tr>
		 * <td> Field Offset:</td>
		 * <td> getUByte(0) & 0x1F</td>
		 * </tr>
		 * </table>
		 * <h3>Header Diagram</h3>
		 * 
		 * <pre>
		 * +------+-----------------+
		 * | CODE | optional header |
		 * +------+-----------------+
		 * </pre>
		 * 
		 * @param value
		 *          new code value
		 */
		@FieldSetter
		public void code(int value) {
			setUByte(0, code() & 0xE0 | value & 0x1F);
		}

		/**
		 * Gets the Ip4.code field. Specifies the optional header type.
		 * <h3>Header Spec</h3>
		 * <table border=1>
		 * <tr>
		 * <td> Protocol Header:</td>
		 * <td> Ip4</td>
		 * </tr>
		 * <tr>
		 * <td> Protocol Family:</td>
		 * <td> Networking</td>
		 * </tr>
		 * <tr>
		 * <td> OSI Layer:</td>
		 * <td> 3</td>
		 * </tr>
		 * <tr>
		 * <td> Field Property:</td>
		 * <td> constant offset</td>
		 * </tr>
		 * <tr>
		 * <td> Field Offset:</td>
		 * <td> getUByte(0) & 0x1F</td>
		 * </tr>
		 * </table>
		 * <h3>Header Diagram</h3>
		 * 
		 * <pre>
		 * +------+-----------------+
		 * | CODE | optional header |
		 * +------+-----------------+
		 * </pre>
		 * 
		 * @return code field value
		 */
		public OptionCode codeEnum() {
			return OptionCode.values()[getUByte(0) & 0x1F];
		}

		/**
		 * Sets the Ip4.code field. Specifies the optional header type.
		 * <h3>Header Spec</h3>
		 * <table border=1>
		 * <tr>
		 * <td> Protocol Header:</td>
		 * <td> Ip4</td>
		 * </tr>
		 * <tr>
		 * <td> Protocol Family:</td>
		 * <td> Networking</td>
		 * </tr>
		 * <tr>
		 * <td> OSI Layer:</td>
		 * <td> 3</td>
		 * </tr>
		 * <tr>
		 * <td> Field Property:</td>
		 * <td> constant offset</td>
		 * </tr>
		 * <tr>
		 * <td> Field Offset:</td>
		 * <td> getUByte(0) & 0x1F</td>
		 * </tr>
		 * </table>
		 * <h3>Header Diagram</h3>
		 * 
		 * <pre>
		 * +------+-----------------+
		 * | CODE | optional header |
		 * +------+-----------------+
		 * </pre>
		 * 
		 * @param value
		 *          new code value
		 */
		public void optionCode(OptionCode value) {
			code(value.ordinal());
		}
	}

	/**
	 * Ip4 optional Loose Source Route header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 3)
	public static class LooseSourceRoute
	    extends Routing {
	}

	/**
	 * Ip4 optional No Operation header. Takes up exactly 1 byte of memory.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 1)
	public static class NoOp
	    extends IpOption {
	}

	/**
	 * Ip4 optional Record Route header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 7)
	public static class RecordRoute
	    extends Routing {
	}

	/**
	 * Ip4 optional Routing header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static abstract class Routing
	    extends IpOption {

		@FieldSetter
		public void address(byte[][] values) {
			for (int i = 0; i < values.length; i++) {
				address(i, values[i]);
			}
		}

		public byte[] address(int index) {
			return getByteArray(index * 4 + 3, 4);
		}

		public void address(int index, byte[] value) {
			setByteArray(index * 4 + 3, value);
		}

		@Field(offset = 24, length = 0, format = "#ip4[]#")
		public byte[][] addressArray() {

			byte[][] ba = new byte[addressCount()][];

			for (int i = 0; i < addressCount(); i++) {
				ba[i] = address(i);
			}

			return ba;
		}

		public int addressCount() {
			return (length() - 3) / 4;
		}

		@Field(offset = 8, length = 8)
		public int length() {
			return getUByte(1);
		}

		@FieldSetter
		public void length(int value) {
			setUByte(1, value);
		}

		@Dynamic(Field.Property.DESCRIPTION)
		public String lengthDescription() {
			return "(" + length() + " - 3)/" + 4 + " = " + addressCount() + " routes";
		}

		@Field(offset = 16, length = 8)
		public int offset() {
			return getUByte(2);
		}

		@FieldSetter
		public void offset(int value) {
			setUByte(2, value);
		}

		@Dynamic(Field.Property.DESCRIPTION)
		public String offsetDescription() {
			return "offset points at route #" + (offset() / 4 - 1) + "";
		}
	}

	/**
	 * Ip4 optional Security header.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 2)
	public static class Security
	    extends IpOption {

		/**
		 * A table of security algorithm types
		 * 
		 * @author Mark Bednarczyk
		 * @author Sly Technologies, Inc.
		 */
		public enum SecurityType {
			CONFIDENTIAL(61749),
			EFTO(30874),
			MMMM(48205),
			PROG(24102),
			RESTRICTED(44819),
			SECRET(55176),
			UNCLASSIFIED(0)

			;
			public static SecurityType valueOf(int type) {
				for (SecurityType t : values()) {
					if (t.getType() == type) {
						return t;
					}
				}

				return null;
			}

			private final int type;

			private SecurityType(int type) {
				this.type = type;

			}

			/**
			 * @return the type
			 */
			public final int getType() {
				return this.type;
			}
		}

		@Field(offset = 4 * 8, length = 16)
		public int compartments() {
			return getUShort(4);
		}

		@FieldSetter
		public void compartments(int value) {
			setUShort(4, value);
		}

		@Field(offset = 8 * 8, length = 24)
		public int control() {
			return (int) (getUShort(8) << 8) | getUByte(10); // 24 bits in
			// BIG_E
		}

		@FieldSetter
		public void control(int value) {
			// TODO: implement Ip4.Security.control field setter
			throw new UnsupportedOperationException("Not implemented yet");
		}

		@Field(offset = 6 * 8, length = 16)
		public int handling() {
			return getUShort(6);
		}

		@Field(offset = 8, length = 8)
		public int length() {
			return getUByte(1);
		}

		@FieldSetter
		public void length(int value) {
			setUByte(1, value);
		}

		@Field(offset = 16, length = 16)
		public int security() {
			return getUShort(2);
		}

		@FieldSetter
		public void security(int value) {
			setUShort(2, value);
		}

		public void security(SecurityType value) {
			security(value.type);
		}

		public SecurityType securityEnum() {
			return SecurityType.valueOf(security());
		}
	}

	/**
	 * Ip4 optional Stream ID header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 8)
	public static class StreamId
	    extends IpOption {

		@Field(offset = 8, length = 8)
		public int length() {
			return getUByte(1);
		}

		@FieldSetter
		public void length(int value) {
			setUByte(1, value);
		}

		@Field(offset = 16, length = 16, format = "%x")
		public int streamId() {
			return getUShort(2);
		}

		@FieldSetter
		public void streamId(int value) {
			setUShort(2, value);
		}
	}

	/**
	 * Ip4 optional Strict Source Route header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 9)
	public static class StrictSourceRoute
	    extends Routing {
	};

	/**
	 * Ip4 optional Timestamp header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = 4)
	public static class Timestamp
	    extends IpOption {

		@HeaderLength
		public static int headerLength(JBuffer buffer, int offset) {
			return buffer.getUByte(1);
		}

		/**
		 * Ip4 optional Timestamp header - a timestamp entry
		 * 
		 * @author Mark Bednarczyk
		 * @author Sly Technologies, Inc.
		 */
		public static class Entry {
			public byte[] address;

			public long timestamp;
		}

		/**
		 * A table of Ip4 Timestamp header flags
		 * 
		 * @author Mark Bednarczyk
		 * @author Sly Technologies, Inc.
		 */
		public enum Flag {
			TIMESTAMP_WITH_IP,
			TIMESTAMPS_PRESPECIFIED
		}

		public final static int FLAG_TIMESTAMP_WITH_IP = 0x01;

		public final static int FLAG_TIMESTAMPS_PRESPECIFIED = 0x2;

		public final static int MASK_FLAGS = 0x0F;

		public final static int MASK_OVERFLOW = 0xF0;

		public byte[] address(int index) {
			if ((flags() & FLAG_TIMESTAMP_WITH_IP) == 0) {
				return null;

			} else {
				return getByteArray(index * 4 + 4, 4);
			}
		}

		@Dynamic(Field.Property.LENGTH)
		public int entriesLength() {
			return (length() - 4) * 8;
		}

		@Field(offset = 4 * 8, format = "%s")
		public Entry[] entries() {
			final int flags = flags();

			if ((flags & FLAG_TIMESTAMP_WITH_IP) == 0) {
				return entriesTimestampOnly();

			} else {
				return entriesWithIp();
			}
		}

		private Entry[] entriesTimestampOnly() {
			final int length = length() - 4;
			final Entry[] entries = new Entry[length / 4];

			for (int i = 4; i < length; i += 8) {
				final Entry entry = entries[i / 8];
				entry.address = getByteArray(i, 4);
				entry.timestamp = getUInt(i + 4);
			}

			return entries;
		}

		private Entry[] entriesWithIp() {
			final int length = length() - 4;
			final Entry[] entries = new Entry[length / 4];

			for (int i = 4; i < length; i += 4) {
				final Entry entry = entries[i / 4];
				entry.timestamp = getUInt(i + 4);
			}

			return entries;
		}

		@Field(offset = 3 * 8 + 4, length = 4)
		public int flags() {
			return (getUByte(3) & MASK_FLAGS);
		}

		@FieldSetter
		public void flags(int value) {
			setUByte(3, value & MASK_FLAGS);
		}

		public Set<Flag> flagsEnum() {
			final Set<Flag> r = EnumSet.noneOf(Flag.class);
			int flags = flags();

			if ((flags & FLAG_TIMESTAMP_WITH_IP) == FLAG_TIMESTAMP_WITH_IP) {
				r.add(Flag.TIMESTAMP_WITH_IP);
			}

			if ((flags & FLAG_TIMESTAMPS_PRESPECIFIED) == FLAG_TIMESTAMPS_PRESPECIFIED) {
				r.add(Flag.TIMESTAMPS_PRESPECIFIED);
			}

			return r;
		}

		@Field(offset = 1 * 8, length = 8)
		public int length() {
			return getUByte(1);
		}

		@FieldSetter
		public void length(int value) {
			setUByte(1, value);
		}

		@Field(offset = 2 * 8, length = 16)
		public int offset() {
			return getUByte(2);
		}

		@FieldSetter
		public void offset(int value) {
			setUByte(2, value);
		}

		@Field(offset = 3 * 8, length = 4)
		public int overflow() {
			return (getUByte(3) & MASK_OVERFLOW) >> 4;
		}

		@FieldSetter
		public void overflow(int value) {
			setUByte(3, value << 4 | flags());
		}

		public long timestamp(int index) {
			if ((flags() & FLAG_TIMESTAMP_WITH_IP) == 0) {
				return getUInt(index * 4 + 4);

			} else {
				return getUInt(index * 4 + 8);
			}
		}

		public int timestampsCount() {
			if ((flags() & FLAG_TIMESTAMP_WITH_IP) == 0) {
				return (length() - 4) / 4;

			} else {
				return (length() - 4) / 8;
			}
		}
	}

	public final static int DIFF_CODEPOINT = 0xFC;

	public final static int DIFF_ECE = 0x01;

	public final static int DIFF_ECT = 0x02;

	public final static int FLAG_DONT_FRAGMENT = 0x2;

	public final static int FLAG_MORE_FRAGMENTS = 0x1;

	public final static int FLAG_RESERVED = 0x4;

	public final static int ID = JProtocol.IP4_ID;

	@Bind(to = Ethernet.class)
	public static boolean bindToEthernet(JPacket packet, Ethernet eth) {
		return eth.type() == 0x800;
	}

	@Bind(to = IEEESnap.class)
	public static boolean bindToSnap(JPacket packet, IEEESnap snap) {
		return snap.pid() == 0x800;
	}

	@HeaderLength
	public static int getHeaderLength(JBuffer buffer, int offset) {
		return (buffer.getUByte(offset) & 0x0F) * 4;
	}

	private int hashcode;

	@Field(offset = 10 * 8, length = 16, format = "%x")
	public int checksum() {
		return getUShort(10);
	}

	@FieldSetter
	public void checksum(int value) {
		setUShort(10, value);
	}

	@BindingVariable(MatchType.FUNCTION)
	public boolean checkType(int type) {
		return type() == type && offset() == 0;
	}

	public void clearFlags(int flags) {
		int o = getUByte(6);
		o &= ~(flags << 5);

		setUByte(6, o);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JHeaderMap#decodeUniqueSubHeaders()
	 */
	@Override
	protected void decodeHeader() {
		optionsBitmap = 0;
		this.hashcode = (id() << 16) ^ sourceToInt() ^ destinationToInt() ^ type();

		// System.out.printf("offset=%d, %s", getOffset(), toHexdump());
		final int hlen = hlen() * 4;

		for (int i = 20; i < hlen; i++) {
			final int id = getUByte(i) & 0x1F;
			optionsOffsets[id] = i;
			optionsBitmap |= (1 << id);

			switch (IpOption.OptionCode.valueOf(id)) {
				case NO_OP:
					optionsLength[id] = 1;
					break;

				case END_OF_OPTION_LIST:
					optionsLength[id] = hlen - i;
					i = hlen;
					break;

				default:
					final int length = getUByte(i + 1); // Length option field
					i += length;
					optionsLength[id] = length;
					break;
			}

			// System.out.printf("i=%d id=%d bitmap=0x%X length=%d\n", i, id,
			// optionsBitmap, optionsLength[id]);
		}
	}

	@Field(offset = 16 * 8, length = 32, format = "#ip4#")
	@FlowKey(index = 0)
	public byte[] destination() {
		return getByteArray(16, 4);
	}

	@FieldSetter
	public void destination(byte[] value) {
		setByteArray(12, value);
	}

	public byte[] destinationToByteArray(byte[] address) {
		if (address.length != 4) {
			throw new IllegalArgumentException("address must be 4 byte long");
		}
		return getByteArray(16, address);
	}

	public int destinationToInt() {
		return getInt(16);
	}

	@Field(offset = 6 * 8, length = 3, format = "%x")
	public int flags() {
		return getUByte(6) >> 5;
	}

	@FieldSetter
	public void flags(int flags) {
		int o = getUByte(6) & 0x1F;
		o |= flags << 5;

		setUByte(6, o);
	}

	@Field(parent = "flags", offset = 2, length = 1, display = "reserved")
	public int flags_Reserved() {
		return (flags() & FLAG_RESERVED) >> 3;
	}

	@Field(parent = "flags", offset = 1, length = 1, display = "do not fragment")
	public int flags_DF() {
		return (flags() & FLAG_DONT_FRAGMENT) >> 1;
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String flags_DFDescription() {
		return (flags_DF() > 0) ? "set" : "not set";
	}

	@Field(parent = "flags", offset = 0, length = 1, display = "more fragments", nicname = "M")
	public int flags_MF() {
		return (flags() & FLAG_MORE_FRAGMENTS) >> 2;
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String flags_MFDescription() {
		return (flags_MF() > 0) ? "set" : "not set";
	}

	@Override
	public int hashCode() {
		return this.hashcode;
	}

	@Field(offset = 0 * 8 + 4, length = 4, format = "%d")
	public int hlen() {
		return getUByte(0) & 0x0F;
	}

	@FieldSetter
	public void hlen(int value) {
		int o = getUByte(0) & 0xF0;
		o |= value & 0x0F;

		setUByte(0, o);
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String hlenDescription() {
		String pre = "" + hlen() + " * 4 = " + (hlen() * 4) + " bytes";
		return (hlen() == 5) ? pre + ", No Ip Options" : pre
		    + ", Ip Options Present";
	}

	@Field(offset = 4 * 8, length = 16, format = "%x")
	public int id() {
		return getUShort(4);
	}

	@FieldSetter
	public void id(int value) {
		setUShort(4, value);
	}

	@Field(offset = 2 * 8, length = 16, format = "%d")
	public int length() {
		return getUShort(2);
	}

	@FieldSetter
	public void length(int value) {
		setUShort(2, value);
	}

	@Field(offset = 6 * 8 + 3, length = 13, format = "%d")
	public int offset() {
		return getUShort(6) & 0x1FFF;
	}

	@FieldSetter
	public void offset(int offset) {
		int o = getUShort(6) & ~0x1FFF;
		o |= offset & 0x1FFF;

		setUShort(6, o);
	}

	@Field(offset = 12 * 8, length = 32, format = "#ip4#")
	@FlowKey(index = 0)
	public byte[] source() {
		return getByteArray(12, 4);
	}

	@FieldSetter
	public void source(byte[] value) {
		setByteArray(12, value);
	}

	public byte[] sourceToByteArray(byte[] address) {
		if (address.length != 4) {
			throw new IllegalArgumentException("address must be 4 byte long");
		}
		return getByteArray(12, address);
	}

	public int sourceToInt() {
		return getInt(12);
	}

	@Field(offset = 1 * 8, length = 8, format = "%x", display = "diffserv")
	public int tos() {
		return getUByte(1);
	}

	@FieldSetter
	public void tos(int value) {
		setUByte(1, value);
	}

	@Field(parent = "tos", offset = 2, length = 6, display = "code point")
	public int tos_Codepoint() {
		return (tos() & DIFF_CODEPOINT) >> 2;
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String tos_CodepointDescription() {
		return (tos_Codepoint() > 0) ? "code point " + tos_Codepoint() : "not set";
	}

	@Field(parent = "tos", offset = 0, length = 1, display = "ECE bit")
	public int tos_ECE() {
		return (tos() & DIFF_ECE) >> 0;
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String tos_ECEDescription() {
		return (tos_ECE() > 0) ? "set" : "not set";
	}

	@Field(parent = "tos", offset = 1, length = 1, display = "ECN bit")
	public int tos_ECN() {
		return (tos() & DIFF_ECT) >> 1;
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String tos_ECNDescription() {
		return (tos_ECN() > 0) ? "set" : "not set";
	}

	@Field(offset = 8 * 8, length = 8, format = "%d", description = "time to live")
	public int ttl() {
		return getUByte(8);
	}

	@FieldSetter
	public void ttl(int value) {
		setUByte(8, value);
	}

	@Field(offset = 9 * 8, length = 8, format = "%d")
	@FlowKey(index = 1)
	public int type() {
		return getUByte(9);
	}

	@FieldSetter
	public void type(int value) {
		setUByte(9, value);
	}

	public void type(Ip4Type type) {
		setUByte(9, type.typeValues[0]);
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String typeDescription() {
		return (offset() == 0) ? "next: " + Ip4Type.toString(type())
		    : "ip fragment";
	}

	public Ip4Type typeEnum() {
		return Ip4Type.valueOf(type());
	}

	@Field(offset = 0 * 8 + 0, length = 4, format = "%d")
	public int version() {
		return getUByte(0) >> 4;
	}

	@FieldSetter
	public void version(int value) {
		setUByte(0, hlen() | value << 4);
	}

}
