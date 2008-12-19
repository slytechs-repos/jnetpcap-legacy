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
import org.jnetpcap.packet.format.JDynamicField;
import org.jnetpcap.packet.format.JField;
import org.jnetpcap.packet.format.JStaticField;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * Layer 2 Tunneling Protocol header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class L2TP
    extends JHeader {

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public final static int FLAG_L = 0x4000;

	public final static int FLAG_O = 0x0200;

	public final static int FLAG_P = 0x0100;

	public final static int FLAG_S = 0x0800;

	public final static int FLAG_T = 0x8000;

	public static final int ID = JProtocol.L2TP_ID;

	public final static int MASK_VERSION = 0x000F;

	/**
	 * Field objects for JFormatter
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] X_FIELDS =
	    {
	        new JField(Style.INT_HEX, "flags", "flags",
	            new JStaticField<L2TP, Integer>(0, 16) {

		            public Integer value(L2TP header) {
			            return header.flags();
		            }
	            }, new JBitField[] {
	                new JBitField("type bit", "T",
	                    new JStaticField<L2TP, Integer>(0, 1, FLAG_T) {

		                    public Integer value(L2TP header) {
			                    return (header.flags() & FLAG_T) >> 15;
		                    }

		                    @Override
		                    public String valueDescription(L2TP header) {
			                    if (value(header) != 0) {
				                    return "control message";
			                    } else {
				                    return "session message";
			                    }
		                    }

	                    }),
	                new JBitField("length bit", "L",
	                    new JStaticField<L2TP, Integer>(1, 1, FLAG_L) {

		                    public Integer value(L2TP header) {
			                    return (header.flags() & FLAG_L) >> 14;
		                    }

		                    @Override
		                    public String valueDescription(L2TP header) {
			                    if (value(header) != 0) {
				                    return "length field is present";
			                    } else {
				                    return "length field is not present";
			                    }
		                    }

	                    }),
	                new JBitField("sequence bit", "S",
	                    new JStaticField<L2TP, Integer>(0, 1, FLAG_S) {

		                    public Integer value(L2TP header) {
			                    return (header.flags() & FLAG_S) >> 11;
		                    }

		                    @Override
		                    public String valueDescription(L2TP header) {
			                    if (value(header) != 0) {
				                    return "Ns and Nr fields are present";
			                    } else {
				                    return "Ns and Nr fields are not present";
			                    }
		                    }

	                    }),
	                new JBitField("offset bit", "O",
	                    new JStaticField<L2TP, Integer>(0, 1, FLAG_O) {

		                    public Integer value(L2TP header) {
			                    return (header.flags() & FLAG_O) >> 10;
		                    }

		                    @Override
		                    public String valueDescription(L2TP header) {
			                    if (value(header) != 0) {
				                    return "offset size field is present";
			                    } else {
				                    return "offset size field is not present";
			                    }
		                    }

	                    }),
	                new JBitField("priority bit", "P",
	                    new JStaticField<L2TP, Integer>(0, 1, FLAG_P) {

		                    public Integer value(L2TP header) {
			                    return (header.flags() & FLAG_P) >> 9;
		                    }

		                    @Override
		                    public String valueDescription(L2TP header) {
			                    if (value(header) != 0) {
				                    return "has priority";
			                    } else {
				                    return "no priority";
			                    }
		                    }

	                    }),
	                new JBitField("version", "V",
	                    new JStaticField<L2TP, Integer>(0, 1, MASK_VERSION) {

		                    public Integer value(L2TP header) {
			                    return header.flags() & MASK_VERSION;
		                    }

		                    @Override
		                    public String valueDescription(L2TP header) {
			                    return "version is " + value(header).toString();
		                    }

	                    }), }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "version", "ver",
	            new JStaticField<L2TP, Integer>(1, 4) {

		            public Integer value(L2TP header) {
			            return header.version();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "length", "len",
	            new JDynamicField<L2TP, Integer>() {

		            /*
								 * (non-Javadoc)
								 * 
								 * @see org.jnetpcap.packet.format.JDynamicField#hasField(org.jnetpcap.packet.JHeader)
								 */
		            @Override
		            public boolean hasField(L2TP header) {
			            setOffset(header.offLength);
			            setLength(16);
			            return header.hasLength();
		            }

		            public Integer value(L2TP header) {
			            return header.length();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "tunnelId", "tid",
	            new JDynamicField<L2TP, Integer>() {

		            /*
								 * (non-Javadoc)
								 * 
								 * @see org.jnetpcap.packet.format.JDynamicField#hasField(org.jnetpcap.packet.JHeader)
								 */
		            @Override
		            public boolean hasField(L2TP header) {
			            setOffset(header.offId);
			            setLength(16);
			            return true;
		            }

		            public Integer value(L2TP header) {
			            return header.tunnelId();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "sessionId", "sid",
	            new JDynamicField<L2TP, Integer>() {

		            /*
								 * (non-Javadoc)
								 * 
								 * @see org.jnetpcap.packet.format.JDynamicField#hasField(org.jnetpcap.packet.JHeader)
								 */
		            @Override
		            public boolean hasField(L2TP header) {
			            setOffset(header.offId + 2);
			            setLength(16);
			            return true;
		            }

		            public Integer value(L2TP header) {
			            return header.sessionId();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "ns", "ns",
	            new JDynamicField<L2TP, Integer>() {

		            /*
								 * (non-Javadoc)
								 * 
								 * @see org.jnetpcap.packet.format.JDynamicField#hasField(org.jnetpcap.packet.JHeader)
								 */
		            @Override
		            public boolean hasField(L2TP header) {
			            setOffset(header.offSequence);
			            setLength(16);
			            return header.hasN();
		            }

		            public Integer value(L2TP header) {
			            return header.ns();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "nr", "nr",
	            new JDynamicField<L2TP, Integer>() {

		            /*
								 * (non-Javadoc)
								 * 
								 * @see org.jnetpcap.packet.format.JDynamicField#hasField(org.jnetpcap.packet.JHeader)
								 */
		            @Override
		            public boolean hasField(L2TP header) {
			            setOffset(header.offSequence + 2);
			            setLength(16);
			            return header.hasN();
		            }

		            public Integer value(L2TP header) {
			            return header.nr();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "offset", "offset",
	            new JDynamicField<L2TP, Integer>() {

		            /*
								 * (non-Javadoc)
								 * 
								 * @see org.jnetpcap.packet.format.JDynamicField#hasField(org.jnetpcap.packet.JHeader)
								 */
		            @Override
		            public boolean hasField(L2TP header) {
			            setOffset(header.offOffset);
			            setLength(16);
			            return header.hasOffset();
		            }

		            public Integer value(L2TP header) {
			            return header.offset();
		            }
	            }),

	    };

	private int offId;

	private int offLength;

	private int offOffset;

	private int offSequence;

	/**
	 * @param id
	 */
	public L2TP() {
		super(ID, X_FIELDS, "l2tp", "l2tp");
		order(BYTE_ORDER);
	}

	public void decodeHeader() {

		int flags = flags();
		int o = 2;

		if (isSet(flags, FLAG_L)) {
			offLength = 2;
			o += 2;
		} else {
			offLength = 0;
		}
		offId = o;
		o += 4;

		if (isSet(flags, FLAG_S)) {
			offSequence = o;
			o += 4;
		} else {
			offSequence = 0;
		}

		if (isSet(flags, FLAG_O)) {
			offOffset = o;
			o += 4;
		} else {
			offOffset = 0;
		}
	}

	public int flags() {
		return getUShort(0);
	}

	public boolean hasLength() {
		return isSet(flags(), FLAG_L);
	}

	public boolean hasN() {
		return isSet(flags(), FLAG_S);
	}

	public boolean hasOffset() {
		return isSet(flags(), FLAG_O);
	}

	private boolean isSet(int i, int m) {
		return (i & m) != 0;
	}

	public int length() {
		return getUShort(offLength);
	}

	public int nr() {
		return getUShort(offSequence + 2);
	}

	public int ns() {
		return getUShort(offSequence);
	}

	public int offset() {
		return getUShort(offOffset);
	}

	public int pad() {
		return getUShort(offOffset + 2);
	}

	public int sessionId() {
		return getUShort(offId + 2);
	}

	public int tunnelId() {
		return getUShort(offId);
	}

	public int version() {
		return getUShort(0) & MASK_VERSION;
	}
}
