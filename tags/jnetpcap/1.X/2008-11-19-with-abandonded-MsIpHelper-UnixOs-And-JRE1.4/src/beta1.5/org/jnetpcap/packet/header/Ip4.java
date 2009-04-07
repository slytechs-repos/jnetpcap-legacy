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

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JProtocol;
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
    extends JHeader {

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
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
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

	        new JField(Style.INT_DEC, Priority.MEDIUM, "time to live", "ttl", "router hops",
	            new JStaticField<Ip4, Integer>(8, 8) {

		            public Integer value(Ip4 header) {
			            return header.ttl();
		            }
	            }),

	        new JField("protocol", "type", new JStaticField<Ip4, Integer>(9, 8) {

		        public Integer value(Ip4 header) {
			        return header.type();
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

	public Ip4() {
		super(ID, X_FIELDS, "ip4", "ip");
		super.order(BYTE_ORDER);
	}

	public int checksum() {
		return getUShort(10);
	}

	public byte[] destination() {
		return getByteArray(16, 4);
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

	public int hlen() {
		return getUByte(0) & 0x0F;
	}

	public int id() {
		return getUShort(4);
	}

	public int length() {
		return getUShort(2);
	}

	public int offset() {
		return getUShort(6) & 0x1FFF;
	}

	public byte[] source() {
		return getByteArray(12, 4);
	}

	public byte[] sourceToByteArray(byte[] address) {
		if (address.length != 4) {
			throw new IllegalArgumentException("address must be 4 byte long");
		}
		return getByteArray(12, address);
	}

	public int tos() {
		return getUByte(1);
	}

	public int ttl() {
		return getUByte(8);
	}

	public int type() {
		return getUByte(9);
	}

	public int version() {
		return getUByte(0) >> 4;
	}
}