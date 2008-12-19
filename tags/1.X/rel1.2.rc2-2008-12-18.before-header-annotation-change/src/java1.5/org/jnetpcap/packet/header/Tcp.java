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
import org.jnetpcap.packet.annotate.BindingVariable;
import org.jnetpcap.packet.format.JBitField;
import org.jnetpcap.packet.format.JField;
import org.jnetpcap.packet.format.JStaticField;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * Tcp/Ip header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Tcp
    extends JHeader {

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public static final int ID = JProtocol.TCP_ID;

	public static final int LENGTH = 20;

	private static final int FLAG_CONG = 0x80;

	private static final int FLAG_ECN = 0x40;

	private static final int FLAG_URG = 0x20;

	private static final int FLAG_ACK = 0x10;

	private static final int FLAG_PUSH = 0x08;

	private static final int FLAG_RESET = 0x04;

	private static final int FLAG_SYNCH = 0x02;

	private static final int FLAG_FIN = 0x01;

	/**
	 * Field objects for JFormatter
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] X_FIELDS =
	    {
	        new JField("source port", "src",
	            new JStaticField<Tcp, Integer>(0, 16) {

		            public Integer value(Tcp header) {
			            return header.source();
		            }
	            }),

	        new JField("destination port", "dst", new JStaticField<Tcp, Integer>(
	            2, 16) {

		        public Integer value(Tcp header) {
			        return header.destination();
		        }
	        }),

	        new JField(Style.LONG_HEX, "sequence", "seq",
	            new JStaticField<Tcp, Long>(4, 32) {

		            public Long value(Tcp header) {
			            return header.seq();
		            }
	            }),

	        new JField(Style.LONG_HEX, "acknowledgement", "ack",
	            new JStaticField<Tcp, Long>(6, 16) {

		            public Long value(Tcp header) {
			            return header.ack();
		            }
	            }),
	        new JField("header length", "hlen", new JStaticField<Tcp, Integer>(
	            12, 4) {

		        public Integer value(Tcp header) {
			        return header.hlen();
		        }

		        @Override
		        public String valueDescription(Tcp header) {
			        return "*4 = " + (header.hlen() * 4) + " bytes";
		        }
	        }),
	        new JField("reserved", "res", new JStaticField<Tcp, Integer>(12, 2) {

		        public Integer value(Tcp header) {
			        return header.reserved();
		        }
	        }),
	        new JField(Style.INT_HEX, "flags", "flags",
	            new JStaticField<Tcp, Integer>(12, 8) {

		            public Integer value(Tcp header) {
			            return header.flags();
		            }
	            }, new JBitField[] {
	                new JBitField("congestion window reduces (CWR)", "C",
	                    new JStaticField<Tcp, Integer>(0, 1, FLAG_CONG) {

		                    public Integer value(Tcp header) {
			                    return (header.flags() & FLAG_CONG) >> 7;
		                    }

		                    @Override
		                    public String valueDescription(Tcp header) {
			                    if (value(header) != 0) {
				                    return "set";
			                    } else {
				                    return "not set";
			                    }
		                    }

	                    }),
	                new JBitField("ecn-echo", "E",
	                    new JStaticField<Tcp, Integer>(0, 1, FLAG_ECN) {

		                    public Integer value(Tcp header) {
			                    return (header.flags() & FLAG_ECN) >> 6;
		                    }

		                    @Override
		                    public String valueDescription(Tcp header) {
			                    if (value(header) != 0) {
				                    return "set";
			                    } else {
				                    return "not set";
			                    }
		                    }

	                    }),
	                new JBitField("urgent pointer", "U",
	                    new JStaticField<Tcp, Integer>(0, 1, FLAG_URG) {

		                    public Integer value(Tcp header) {
			                    return (header.flags() & FLAG_URG) >> 5;
		                    }

		                    @Override
		                    public String valueDescription(Tcp header) {
			                    if (value(header) != 0) {
				                    return "pointer set";
			                    } else {
				                    return "pointer not set";
			                    }
		                    }

	                    }),
	                new JBitField("acknowledgement", "A",
	                    new JStaticField<Tcp, Integer>(0, 1, FLAG_ACK) {

		                    public Integer value(Tcp header) {
			                    return (header.flags() & FLAG_ACK) >> 4;
		                    }

		                    @Override
		                    public String valueDescription(Tcp header) {
			                    if (value(header) != 0) {
				                    return "is present";
			                    } else {
				                    return "is not present";
			                    }
		                    }

	                    }),
	                new JBitField("push", "P", new JStaticField<Tcp, Integer>(0,
	                    1, FLAG_PUSH) {

		                public Integer value(Tcp header) {
			                return (header.flags() & FLAG_PUSH) >> 3;
		                }

		                @Override
		                public String valueDescription(Tcp header) {
			                if (value(header) != 0) {
				                return "flag is set";
			                } else {
				                return "flag is not set";
			                }
		                }

	                }),
	                new JBitField("reset", "R", new JStaticField<Tcp, Integer>(0,
	                    1, FLAG_RESET) {

		                public Integer value(Tcp header) {
			                return (header.flags() & FLAG_RESET) >> 2;
		                }

		                @Override
		                public String valueDescription(Tcp header) {
			                if (value(header) != 0) {
				                return "flag is set";
			                } else {
				                return "flag is not set";
			                }
		                }

	                }),
	                new JBitField("synchronize", "S",
	                    new JStaticField<Tcp, Integer>(0, 1, FLAG_SYNCH) {

		                    public Integer value(Tcp header) {
			                    return (header.flags() & FLAG_SYNCH) >> 1;
		                    }

		                    @Override
		                    public String valueDescription(Tcp header) {
			                    if (value(header) != 0) {
				                    return "flag is set";
			                    } else {
				                    return "flag is not set";
			                    }
		                    }

	                    }),
	                new JBitField("finish", "F", new JStaticField<Tcp, Integer>(
	                    0, 1, FLAG_FIN) {

		                public Integer value(Tcp header) {
			                return (header.flags() & FLAG_FIN);
		                }

		                @Override
		                public String valueDescription(Tcp header) {
			                if (value(header) != 0) {
				                return "flag is set";
			                } else {
				                return "flag is not set";
			                }
		                }

	                }), }),
	        new JField(Style.INT_DEC, Priority.MEDIUM, "window", "win", "bytes",
	            new JStaticField<Tcp, Integer>(14, 16) {

		            public Integer value(Tcp header) {
			            return header.window();
		            }

		            @Override
		            public String valueDescription(Tcp header) {
			            return "" + (header.window() / 1024) + "Kb";
		            }

	            }),
	        new JField(Style.INT_HEX, "checksum", "crc",
	            new JStaticField<Tcp, Integer>(16, 2) {

		            public Integer value(Tcp header) {
			            return header.checksum();
		            }
	            }),
	        new JField("urgent", "urg", new JStaticField<Tcp, Integer>(18, 2) {

		        public Integer value(Tcp header) {
			        return header.urgent();
		        }
	        }),

	    };

	/**
	 * @param id
	 */
	public Tcp() {
		super(ID, X_FIELDS, "tcp", "tcp");
		order(BYTE_ORDER);
	}

	@BindingVariable
	public int source() {
		return getUShort(0);
	}

	@BindingVariable
	public int destination() {
		return getUShort(2);
	}

	public long seq() {
		return getUInt(4);
	}

	public long ack() {
		return getUInt(8);
	}

	public int hlen() {
		return (getUByte(12) & 0xF0) >> 4;
	}

	public int reserved() {
		return getUShort(12) & 0x0F00;
	}

	public int flags() {
		return getUShort(12) & 0x00FF;
	}

	public int window() {
		return getUShort(14);
	}

	public int checksum() {
		return getUShort(16);
	}

	public int urgent() {
		return getUShort(18);
	}

}
