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

import java.nio.ByteOrder;
import java.util.EnumSet;
import java.util.Set;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.format.JBitField;
import org.jnetpcap.packet.format.JField;
import org.jnetpcap.packet.format.JStaticField;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * IP version 4 network protocol header.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Ip4
    extends JHeaderMap<Ip4> {

	/**
	 * A table of IpTypes and their names
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Ip4Type {
		/**
		 * Ttransmission control protocol
		 */
		TCP(6, "tcp - transmission control protocol version 6"),

		/**
		 * Unreliable datagram protocol
		 */
		UDP(17, "udp - unreliable datagram protocol"),

		/**
		 * Internet control messaging protocol
		 */
		ICMP(1, "icmp - internet message control protocol"), ;
		private final int id;

		private final String description;

		private Ip4Type(int id) {
			this.id = id;
			this.description = name().toLowerCase();
		}

		private Ip4Type(int id, String description) {
			this.id = id;
			this.description = description;

		}

		/**
		 * Name of the constant
		 * 
		 * @param id
		 *          ip type number
		 * @return constants name
		 */
		public static String toString(int id) {
			for (Ip4Type t : values()) {
				if (t.id == id) {
					return t.description;
				}
			}

			return null;
		}

		/**
		 * Converts contant to numerical ip type
		 * 
		 * @return Ip4 type number
		 */
		public final int getId() {
			return this.id;
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
		 * Converts a numerical type to constant
		 * 
		 * @param type
		 *          Ip4 type number
		 * @return constant or null if not found
		 */
		public static Ip4Type valueOf(int type) {
			for (Ip4Type t : values()) {
				if (t.id == type) {
					return t;
				}
			}

			return null;
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
			END_OF_OPTION_LIST,
			/* 1 */
			NO_OP,
			/* 2 */
			SECURITY,
			/* 3 */
			LOOSE_SOURCE_ROUTE,
			/* 4 */
			TIMESTAMP,
			/* 5 */
			UNASSIGNED1,
			/* 6 */
			UNASSIGNED2,
			/* 7 */
			RECORD_ROUTE,
			/* 8 */
			STREAM_ID,
			/* 9 */
			STRICT_SOURCE_ROUTE,
		}

		protected IpOption(int id, JField[] fields, String name, String nicname) {
			super(id, fields, name, nicname);
			order(ByteOrder.BIG_ENDIAN);
		}

		protected IpOption(int id, String name, String nicname) {
			super(id, name, nicname);
			order(ByteOrder.BIG_ENDIAN);
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
		public void code(int value) {
			setUByte(0, code() & 0xE0 | value & 0x1F);
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
	}

	/**
	 * Ip4 optional Loose Source Route header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class LooseSourceRoute
	    extends Routing {
		public LooseSourceRoute() {
			super(OptionCode.LOOSE_SOURCE_ROUTE.ordinal(), "loose source route", "NP");
		}
	};

	/**
	 * Ip4 optional No Operation header. Takes up exactly 1 byte of memory.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class NoOp
	    extends IpOption {
		public NoOp() {
			super(OptionCode.NO_OP.ordinal(), "NOP", "NOP");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JHeader#getFields()
		 */
		@Override
		public JField[] getFields() {
			return new JField[0];
		}

	}

	/**
	 * Ip4 optional Security header.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class Security
	    extends IpOption {

		public final static JField[] X_FIELDS =
		    {
		        new JField("code", "code", new JStaticField<Ip4.Security, Integer>(
		            0, 16) {

			        public Integer value(Ip4.Security header) {
				        return header.code();
			        }
		        }),
		        new JField("length", "len",
		            new JStaticField<Ip4.Security, Integer>(0, 16) {

			            public Integer value(Ip4.Security header) {
				            return header.length();
			            }
		            }),
		        new JField("security", "sec",
		            new JStaticField<Ip4.Security, Integer>(0, 16) {

			            public Integer value(Ip4.Security header) {
				            return header.security();
			            }
		            }),
		        new JField("compartments", "comp",
		            new JStaticField<Ip4.Security, Integer>(0, 16) {

			            public Integer value(Ip4.Security header) {
				            return header.compartments();
			            }
		            }),
		        new JField("handling", "hand",
		            new JStaticField<Ip4.Security, Integer>(0, 32) {

			            public Integer value(Ip4.Security header) {
				            return header.handling();
			            }
		            }),
		        new JField("control", "cont",
		            new JStaticField<Ip4.Security, Integer>(0, 24) {

			            public Integer value(Ip4.Security header) {
				            return header.control();
			            }
		            }), };

		public Security() {
			super(OptionCode.SECURITY.ordinal(), X_FIELDS, "Security", "sec");
		}

		public int length() {
			return getUByte(1);
		}

		public void length(int value) {
			setUByte(1, value);
		}

		public int security() {
			return getUShort(2);
		}

		public void security(int value) {
			setUShort(2, value);
		}

		public void security(SecurityType value) {
			security(value.type);
		}

		public SecurityType securityEnum() {
			return SecurityType.valueOf(security());
		}

		/**
		 * A table of security algorithm types
		 * 
		 * @author Mark Bednarczyk
		 * @author Sly Technologies, Inc.
		 */
		public enum SecurityType {
			UNCLASSIFIED(0),
			CONFIDENTIAL(61749),
			EFTO(30874),
			MMMM(48205),
			PROG(24102),
			RESTRICTED(44819),
			SECRET(55176)

			;
			private final int type;

			private SecurityType(int type) {
				this.type = type;

			}

			public static SecurityType valueOf(int type) {
				for (SecurityType t : values()) {
					if (t.getType() == type) {
						return t;
					}
				}

				return null;
			}

			/**
			 * @return the type
			 */
			public final int getType() {
				return this.type;
			}
		}

		public int compartments() {
			return getUShort(4);
		}

		public int handling() {
			return getUShort(6);
		}

		public int control() {
			return (int) (getUShort(8) << 8) & getUByte(10); // 24 bits in BIG_E
		}
	}

	/**
	 * Ip4 optional Stream ID header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class StreamId
	    extends IpOption {

		public final static JField[] X_FIELDS =
		    {
		        new JField("code", "code", new JStaticField<Ip4.StreamId, Integer>(
		            0, 16) {

			        public Integer value(Ip4.StreamId header) {
				        return header.code();
			        }
		        }),
		        new JField("length", "len",
		            new JStaticField<Ip4.StreamId, Integer>(0, 16) {

			            public Integer value(Ip4.StreamId header) {
				            return header.length();
			            }
		            }),
		        new JField("streamId", "id",
		            new JStaticField<Ip4.StreamId, Integer>(0, 16) {

			            public Integer value(Ip4.StreamId header) {
				            return header.streamId();
			            }
		            }),

		    };

		public StreamId() {
			super(OptionCode.STREAM_ID.ordinal(), X_FIELDS, "stream id", "np");
		}

		public int length() {
			return getUByte(1);
		}

		public void length(int value) {
			setUByte(1, value);
		}

		public int streamId() {
			return getUShort(2);
		}

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
	public static class StrictSourceRoute
	    extends Routing {
		public StrictSourceRoute() {
			super(OptionCode.STRICT_SOURCE_ROUTE.ordinal(), "strct source route",
			    "NP");
		}
	}

	/**
	 * Ip4 optional Timestamp header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class Timestamp
	    extends IpOption {

		public final static int MASK_FLAGS = 0x0F;

		public final static int MASK_OVERFLOW = 0xF0;

		public final static int FLAG_TIMESTAMP_WITH_IP = 0x01;

		public final static int FLAG_TIMESTAMPS_PRESPECIFIED = 0x2;

		public Timestamp() {
			super(OptionCode.TIMESTAMP.ordinal(), "timestamp", "ts");
		}

		public int length() {
			return getUByte(1);
		}

		public void length(int value) {
			setUByte(1, value);
		}

		public int offset() {
			return getUByte(2);
		}

		public void offset(int value) {
			setUByte(2, value);
		}

		public int overflow() {
			return (getUByte(3) & MASK_OVERFLOW) >> 4;
		}

		public void overflow(int value) {
			setUByte(3, value << 4 | flags());
		}

		public int flags() {
			return (getUByte(3) & MASK_FLAGS);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JHeader#getFields()
		 */
		@Override
		public JField[] getFields() {
			int size = timestampsCount();
			int count = size;

			if ((flags() & FLAG_TIMESTAMP_WITH_IP) == FLAG_TIMESTAMP_WITH_IP) {
				size *= 2;
			}

			JField[] fields = new JField[size + 4];
			fields[0] =
			    new JField("code", "code", new JStaticField<Ip4.Timestamp, Integer>(
			        0, 8) {

				    public Integer value(Ip4.Timestamp header) {
					    return header.code();
				    }
			    });

			fields[1] =
			    new JField("length", "len", new JStaticField<Ip4.Timestamp, Integer>(
			        8, 8) {

				    public Integer value(Ip4.Timestamp header) {
					    return header.length();
				    }
			    });

			fields[2] =
			    new JField("offset", "ptr", new JStaticField<Ip4.Timestamp, Integer>(
			        16, 4) {

				    public Integer value(Ip4.Timestamp header) {
					    return header.offset();
				    }
			    });

			fields[3] =
			    new JField(Style.INT_HEX, "flags", "flg",
			        new JStaticField<Ip4.Timestamp, Integer>(20, 4) {

				        public Integer value(Ip4.Timestamp header) {
					        return header.flags();
				        }
			        }, new JBitField[] {
			            new JBitField(" path type", "TP",
			                new JStaticField<Ip4.Timestamp, Integer>(1, 1,
			                    FLAG_TIMESTAMPS_PRESPECIFIED) {

				                public Integer value(Ip4.Timestamp header) {
					                return (header.flags() & FLAG_TIMESTAMPS_PRESPECIFIED);
				                }

				                @Override
				                public String valueDescription(Ip4.Timestamp header) {
					                if (value(header) != 0) {
						                return "predefined";
					                } else {
						                return "not defined";
					                }
				                }

			                }),
			            new JBitField("stamp type", "TA",
			                new JStaticField<Ip4.Timestamp, Integer>(0, 1,
			                    FLAG_TIMESTAMP_WITH_IP) {

				                public Integer value(Ip4.Timestamp header) {
					                return (header.flags() & FLAG_TIMESTAMP_WITH_IP) >> 1;
				                }

				                @Override
				                public String valueDescription(Ip4.Timestamp header) {
					                if (value(header) != 0) {
						                return "timestamp with IP address";
					                } else {
						                return "timestamp only";
					                }
				                }

			                }), });

			count += 4;
			for (int f = 4, o = 4; f < count;) {

				if ((flags() & FLAG_TIMESTAMP_WITH_IP) == FLAG_TIMESTAMP_WITH_IP) {
					final int offset = o;
					fields[f] =
					    new JField(Style.BYTE_ARRAY_IP4_ADDRESS, "destination", "dst",
					        new JStaticField<Ip4.Timestamp, byte[]>(16, 32) {

						        public byte[] value(Ip4.Timestamp header) {
							        return header.getByteArray(offset, 4);
						        }
					        });

					f++;
					o += 4;
				}

				final int offset = o;

				fields[f] =
				    new JField(Style.LONG_DEC, "timestamp", "ts",
				        new JStaticField<Ip4.Timestamp, Long>(16, 32) {

					        public Long value(Ip4.Timestamp header) {
						        return header.getUInt(offset);
					        }

					        /*
									 * (non-Javadoc)
									 * 
									 * @see org.jnetpcap.packet.format.JStaticField#valueDescription(org.jnetpcap.packet.JHeader)
									 */
					        @Override
					        public String valueDescription(Timestamp header) {
						        long v = header.getUInt(offset);
						        if (v == 0) {
							        return null;
						        }

						        float f = v;
						        f /= 1000;

						        return FormatUtils.formatTimeInMillis(v);
					        }
				        });

				f++;
				o += 4;
			}

			return fields;
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

		public int timestampsCount() {
			if ((flags() & FLAG_TIMESTAMP_WITH_IP) == 0) {
				return (length() - 4) / 4;

			} else {
				return (length() - 4) / 8;
			}
		}

		public long timestamp(int index) {
			if ((flags() & FLAG_TIMESTAMP_WITH_IP) == 0) {
				return getUInt(index * 4 + 4);

			} else {
				return getUInt(index * 4 + 8);
			}
		}

		public byte[] address(int index) {
			if ((flags() & FLAG_TIMESTAMP_WITH_IP) == 0) {
				return null;

			} else {
				return getByteArray(index * 4 + 4, 4);
			}
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
	}

	public final static JHeader[] X_HEADERS = {
	    new Ip4.Timestamp(),
	    new Ip4.NoOp(),
	    new Ip4.LooseSourceRoute(),
	    new Ip4.StrictSourceRoute(),
	    new Ip4.RecordRoute(),
	    new Ip4.Security(),
	    new Ip4.StreamId(), };

	/**
	 * Ip4 optional Record Route header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class RecordRoute
	    extends Routing {

		/**
		 * @param id
		 * @param name
		 * @param nicname
		 */
		public RecordRoute() {
			super(OptionCode.RECORD_ROUTE.ordinal(), "record routing", "rr");
		}

	}

	/**
	 * Ip4 optional Routing header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static abstract class Routing
	    extends IpOption {

		public Routing(int id, String name, String nicname) {
			super(id, name, nicname);
		}

		public int length() {
			return getUByte(1);
		}

		public void length(int value) {
			setUByte(1, value);
		}

		public int offset() {
			return getUByte(2);
		}

		public void offset(int value) {
			setUByte(2, value);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JHeader#getFields()
		 */
		@Override
		public JField[] getFields() {
			int size = addressCount();

			JField[] fields = new JField[size + 3];
			fields[0] =
			    new JField("code", "code", new JStaticField<Ip4.Routing, Integer>(0,
			        8) {

				    public Integer value(Ip4.Routing header) {
					    return header.code();
				    }
			    });

			fields[1] =
			    new JField("length", "len", new JStaticField<Ip4.Routing, Integer>(8,
			        8) {

				    public Integer value(Ip4.Routing header) {
					    return header.length();
				    }
			    });

			fields[2] =
			    new JField("offset", "ptr", new JStaticField<Ip4.Routing, Integer>(
			        16, 4) {

				    public Integer value(Ip4.Routing header) {
					    return header.offset();
				    }
			    });

			for (int f = 3, o = 3; f < size; f++, o += 4) {

				final int offset = o;
				fields[f] =
				    new JField(Style.BYTE_ARRAY_IP4_ADDRESS, "route", "rt",
				        new JStaticField<Ip4.Routing, byte[]>(o * 8, 32) {

					        public byte[] value(Ip4.Routing header) {
						        return header.getByteArray(offset, 4);
					        }
				        });
			}

			return fields;
		}

		public int addressCount() {
			return (length() - 3) / 4;
		}

		public byte[] address(int index) {
			return getByteArray(index * 4 + 3, 4);
		}

		public void address(int index, byte[] value) {
			setByteArray(index * 4 + 3, value);
		}

		public void address(byte[][] values) {
			for (int i = 0; i < values.length; i++) {
				address(i, values[i]);
			}
		}

		public byte[][] addressArray() {

			byte[][] ba = new byte[addressCount()][];

			for (int i = 0; i < addressCount(); i++) {
				ba[i] = address(i);
			}

			return ba;
		}
	}

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public final static int DIFF_CODEPOINT = 0xFC;

	public final static int DIFF_ECE = 0x01;

	public final static int DIFF_ECT = 0x02;

	public final static int FLAG_DONT_FRAGMENT = 0x2;

	public final static int FLAG_MORE_FRAGEMNTS = 0x1;

	public final static int FLAG_RESERVED = 0x4;

	public static final int ID = JProtocol.IP4_ID;

	/**
	 * Field objects for JFormatter
	 */
	public final static JField[] X_FIELDS =
	    {
	        new JField("version", "ver", new JStaticField<Ip4, Integer>(0, 4) {

		        public Integer value(Ip4 header) {
			        return header.version();
		        }
	        }),

	        new JField("hlen", "hlen", new JStaticField<Ip4, Integer>(0, 4) {

		        public Integer value(Ip4 header) {
			        return header.hlen();
		        }

		        @Override
		        public String valueDescription(Ip4 header) {
			        return "*4 = " + (header.hlen() * 4) + " bytes";
		        }

	        }),

	        new JField(Style.INT_HEX, "diffs", "diffs",
	            new JStaticField<Ip4, Integer>(1, 8) {

		            public Integer value(Ip4 header) {
			            return header.tos();
		            }
	            }, new JBitField[] {
	                new JBitField("reserved bit", "R",
	                    new JStaticField<Ip4, Integer>(1, 6, DIFF_CODEPOINT) {

		                    public Integer value(Ip4 header) {
			                    return (header.tos() & DIFF_CODEPOINT) >> 2;
		                    }

		                    @Override
		                    public String valueDescription(Ip4 header) {
			                    if (value(header) != 0) {
				                    return "code point " + value(header);
			                    } else {
				                    return "not set";
			                    }
		                    }
	                    }),
	                new JBitField("ECN bit", "E", new JStaticField<Ip4, Integer>(
	                    1, 1, DIFF_ECT) {

		                public Integer value(Ip4 header) {
			                return (header.tos() & DIFF_ECT) >> 1;
		                }

		                @Override
		                public String valueDescription(Ip4 header) {
			                int v = value(header);

			                return "ECN capable transport: "
			                    + ((v != 0) ? "yes" : "no");
		                }
	                }),

	                new JBitField("ECE bit", "C", new JStaticField<Ip4, Integer>(
	                    1, 1, DIFF_ECE) {

		                public Integer value(Ip4 header) {
			                return (header.tos() & DIFF_ECE);
		                }

		                @Override
		                public String valueDescription(Ip4 header) {
			                int v = value(header);

			                return "ECE-CE: " + ((v != 0) ? "yes" : "no");
		                }
	                }), }) {

	        },

	        new JField("length", "length", new JStaticField<Ip4, Integer>(2, 16) {

		        public Integer value(Ip4 header) {
			        return header.length();
		        }
	        }),

	        new JField(
	            Style.INT_HEX,
	            "flags",
	            "flags",
	            new JStaticField<Ip4, Integer>(6, 3) {

		            public Integer value(Ip4 header) {
			            return header.flags();
		            }
	            },
	            new JBitField[] {
	                new JBitField("reserved bit", "R",
	                    new JStaticField<Ip4, Integer>(0, 1, FLAG_RESERVED) {

		                    public Integer value(Ip4 header) {
			                    return (header.flags() & FLAG_RESERVED) >> 2;
		                    }

		                    @Override
		                    public String valueDescription(Ip4 header) {
			                    if (value(header) != 0) {
				                    return "set";
			                    } else {
				                    return "not set";
			                    }
		                    }
	                    }),

	                new JBitField("don't fragment", "D",
	                    new JStaticField<Ip4, Integer>(0, 1, FLAG_DONT_FRAGMENT) {

		                    public Integer value(Ip4 header) {
			                    return (header.flags() & FLAG_DONT_FRAGMENT) >> 1;
		                    }

		                    @Override
		                    public String valueDescription(Ip4 header) {
			                    if (value(header) != 0) {
				                    return "set";
			                    } else {
				                    return "not set";
			                    }
		                    }
	                    }),

	                new JBitField(
	                    "more fragments",
	                    "F",
	                    new JStaticField<Ip4, Integer>(0, 1, FLAG_MORE_FRAGEMNTS) {

		                    public Integer value(Ip4 header) {
			                    return (header.flags() & FLAG_MORE_FRAGEMNTS) >> 1;
		                    }

		                    @Override
		                    public String valueDescription(Ip4 header) {
			                    if (value(header) != 0) {
				                    return "set";
			                    } else {
				                    return "not set";
			                    }
		                    }
	                    }),

	            }) {
	        },

	        new JField(Style.INT_HEX, "id", "id", new JStaticField<Ip4, Integer>(
	            4, 16) {

		        public Integer value(Ip4 header) {
			        return header.id();
		        }
	        }),

	        new JField("offset", "offset", new JStaticField<Ip4, Integer>(6, 13) {

		        public Integer value(Ip4 header) {
			        return header.offset();
		        }
	        }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "time to live", "ttl",
	            "router hops", new JStaticField<Ip4, Integer>(8, 8) {

		            public Integer value(Ip4 header) {
			            return header.ttl();
		            }
	            }),

	        new JField("protocol", "type", new JStaticField<Ip4, Integer>(9, 8) {

		        public Integer value(Ip4 header) {
			        return header.type();
		        }

		        @Override
		        public String valueDescription(Ip4 header) {
			        final String s = Ip4Type.toString(header.type());
			        if (s == null) {
				        return super.valueDescription(header);
			        } else {
				        return s;
			        }
		        }
	        }),

	        new JField(Style.INT_HEX, "header checksum", "crc",
	            new JStaticField<Ip4, Integer>(10, 16) {

		            public Integer value(Ip4 header) {
			            return header.checksum();
		            }
	            }),

	        new JField(Style.BYTE_ARRAY_IP4_ADDRESS, "source", "src",
	            new JStaticField<Ip4, byte[]>(12, 32) {

		            public byte[] value(Ip4 header) {
			            return header.source();
		            }
	            }),

	        new JField(Style.BYTE_ARRAY_IP4_ADDRESS, "destination", "dst",
	            new JStaticField<Ip4, byte[]>(16, 32) {

		            public byte[] value(Ip4 header) {
			            return header.destination();
		            }
	            }),

	    };

	private int hashcode = super.hashCode();

	/**
	 * Uses an special hashcode, that will be the same for packets that have the
	 * following fields the same:
	 * <ul>
	 * <li> source address
	 * <li> destination address;
	 * <li> id
	 * <li> type
	 * </ul>
	 * The hashcode is generated using the following formula:
	 * <code>int hash = (id() << 16) ^ source() ^ destination() ^ type();</code>
	 */
	@Override
	public int hashCode() {
		return hashcode;
	}

	public Ip4() {
		super(ID, X_FIELDS, "ip4", "ip", X_HEADERS);
		super.order(BYTE_ORDER);
	}

	public int checksum() {
		return getUShort(10);
	}

	public void checksum(int value) {
		setUShort(10, value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JHeader#decode()
	 */
	@Override
	public void decodeHeader() {
		optionsBitmap = 0;
		this.hashcode = (id() << 16) ^ sourceToInt() ^ destinationToInt() ^ type();

		final int hlen = hlen() * 4;

		for (int i = 20; i < hlen; i++) {
			final int id = getUByte(i) & 0x1F;
			optionsOffsets[id] = i;
			optionsBitmap |= (1 << id);

			switch (IpOption.OptionCode.values()[id]) {
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
		}
	}

	public byte[] destination() {
		return getByteArray(16, 4);
	}

	public void destination(byte[] value) {
		setByteArray(12, value);
	}

	public int destinationToInt() {
		return getInt(16);
	}

	public byte[] destinationToByteArray(byte[] address) {
		if (address.length != 4) {
			throw new IllegalArgumentException("address must be 4 byte long");
		}
		return getByteArray(16, address);
	}

	public int flags() {
		return getUByte(6) >> 5;
	}

	public void flags(int flags) {
		int o = getUByte(6) & 0x1F;
		o |= flags << 5;

		setUByte(6, o);
	}

	public void clearFlags(int flags) {
		int o = getUByte(6);
		o &= ~(flags << 5);

		setUByte(6, o);
	}

	public int hlen() {
		return getUByte(0) & 0x0F;
	}

	public void hlen(int value) {
		int o = getUByte(0) & 0xF0;
		o |= value & 0x0F;

		setUByte(0, o);
	}

	public int id() {
		return getUShort(4);
	}

	public void id(int value) {
		setUShort(4, value);
	}

	public int length() {
		return getUShort(2);
	}

	public void length(int value) {
		setUShort(2, value);
	}

	public int offset() {
		return getUShort(6) & 0x1FFF;
	}

	public void offset(int offset) {
		int o = getUShort(6) & ~0x1FFF;
		o |= offset & 0x1FFF;

		setUShort(6, o);
	}

	public byte[] source() {
		return getByteArray(12, 4);
	}

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

	public int tos() {
		return getUByte(1);
	}

	public void tos(int value) {
		setUByte(1, value);
	}

	public int ttl() {
		return getUByte(8);
	}

	public void ttl(int value) {
		setUByte(8, value);
	}

	public int type() {
		return getUByte(9);
	}

	public void type(int value) {
		setUByte(9, value);
	}

	public void type(Ip4Type type) {
		setUByte(9, type.id);
	}

	public Ip4Type typeEnum() {
		return Ip4Type.valueOf(type());
	}

	public int version() {
		return getUByte(0) >> 4;
	}

	public void version(int value) {
		setUByte(0, hlen() | value << 4);
	}
}