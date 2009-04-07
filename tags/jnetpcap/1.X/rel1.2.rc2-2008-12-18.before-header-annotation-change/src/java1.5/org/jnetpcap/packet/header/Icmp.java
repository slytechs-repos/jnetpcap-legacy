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
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.format.JField;
import org.jnetpcap.packet.format.JStaticField;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * ICMP header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Icmp
    extends JHeaderMap<Icmp> {

	/**
	 * ICMP Echo header (ping) baseclass definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class Echo
	    extends JSubHeader<Icmp> {
		public final static JField[] X_FIELDS =
		    {
		        new JField("id", "id", new JStaticField<Icmp.Echo, Integer>(0, 16) {

			        public Integer value(Icmp.Echo header) {
				        return header.id();
			        }
		        }),
		        new JField("sequence", "seq", new JStaticField<Icmp.Echo, Integer>(
		            0, 16) {

			        public Integer value(Icmp.Echo header) {
				        return header.sequence();
			        }
		        }),
		        new JField("data length", "data length",
		            new JStaticField<Icmp.Echo, String>(0, 16) {

			            public String value(Icmp.Echo header) {
				            return "(" + (header.getLength() - 4) + " bytes)";
			            }

		            }),

		        new JField(Style.BYTE_ARRAY_HEX_DUMP, "data", "data",
		            new JStaticField<Icmp.Echo, byte[]>(0, 16) {

			            public byte[] value(Icmp.Echo header) {
				            return header.data();
			            }
		            }), };

		/**
		 * @param id
		 * @param fields
		 * @param name
		 * @param nicname
		 */
		public Echo(int id, String name, String nicname) {
			super(id, X_FIELDS, name, nicname);
		}

		public byte[] data() {
			return getByteArray(4, getLength() - 4);
		}

		public int id() {
			return getUShort(0);
		}

		public int sequence() {
			return getUShort(2);
		}
	};

	/**
	 * ICMP Echo Reply header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class EchoReply
	    extends Echo {
		public EchoReply() {
			super(IcmpType.ECHO_REPLY.id, "EchoReply", "echo reply");
		}
	}

	/**
	 * ICMP Echo Request header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class EchoRequest
	    extends Echo {
		public EchoRequest() {
			super(IcmpType.ECHO_REQUEST.id, "EchoRequest", "echo request");
		}
	}

	/**
	 * Base class for various ICMP Headers that contain a reserved field
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static abstract class Reserved
	    extends JSubHeader<Icmp> {
		public final static JField[] X_FIELDS =
		    { new JField("reserved", "reserved",
		        new JStaticField<Icmp.DestinationUnreachable, Long>(0, 4) {

			        public Long value(Icmp.DestinationUnreachable header) {
				        return header.reserved();
			        }
		        }), };

		/**
		 * @param id
		 * @param fields
		 * @param name
		 */
		public Reserved(int id, String name) {
			super(id, X_FIELDS, name);
		}

		public long reserved() {
			return getUInt(0);
		}
	}

	/**
	 * ICMP Destination Unreachable header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class DestinationUnreachable
	    extends Reserved {
		public DestinationUnreachable() {
			super(IcmpType.DESTINATION_UNREACHABLE.id, "DestUnreachable");
		}
	}

	/**
	 * ICMP Source Quence header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class SourceQuench
	    extends Reserved {
		public SourceQuench() {
			super(IcmpType.SOURCE_QUENCH.id, "SourceQuench");
		}
	}

	/**
	 * ICMP Redirect header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class Redirect
	    extends JSubHeader<Icmp> {

		public final static JField[] X_FIELDS =
		    { new JField(Style.BYTE_ARRAY_DOT_ADDRESS, "gateway", "gateway",
		        new JStaticField<Icmp.Redirect, byte[]>(0, 4) {

			        public byte[] value(Icmp.Redirect header) {
				        return header.gateway();
			        }
		        }), };

		public Redirect() {
			super(IcmpType.REDIRECT.id, X_FIELDS, "redirect");
		}

		public byte[] gateway() {
			return getByteArray(0, 4);
		}
	}

	/**
	 * ICMP Paramater Protoblem header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class ParamProblem
	    extends JSubHeader<Icmp> {

		public final static JField[] X_FIELDS =
		    {
		        new JField("pointer", "ptr",
		            new JStaticField<Icmp.ParamProblem, Integer>(0, 4) {

			            public Integer value(Icmp.ParamProblem header) {
				            return header.pointer();
			            }
		            }),
		        new JField("reserved", "reserved",
		            new JStaticField<Icmp.ParamProblem, Integer>(0, 4) {

			            public Integer value(Icmp.ParamProblem header) {
				            return header.reserved();
			            }
		            }), };

		public ParamProblem() {
			super(IcmpType.REDIRECT.id, X_FIELDS, "redirect");
		}

		public int pointer() {
			return getUByte(0);
		}

		public int reserved() {
			return (int) (getUInt(0) & 0x00FFFFFFL);
		}
	}

	/**
	 * A table of Icmp sub-codes per Icmp type
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum IcmpCode {
		DESTINATION_NETWORK_REDIRECT(IcmpType.DESTINATION_UNREACHABLE, 0),
		DESTINATION_PROTOCOL_UNREACHABLE(IcmpType.DESTINATION_UNREACHABLE, 1),
		DESTINATION_PORT_UNREACHABLE(IcmpType.DESTINATION_UNREACHABLE, 3),
		DESTINATION_NO_FRAG(IcmpType.DESTINATION_UNREACHABLE, 4),
		DESTINATION_SOURCE_ROUTE(IcmpType.DESTINATION_UNREACHABLE, 5),
		DESTINATION_NETWORK_UNREACHABLE(IcmpType.DESTINATION_UNREACHABLE, 6),
		DESTINATION_HOST_UNKNOWN(IcmpType.DESTINATION_UNREACHABLE, 7),
		DESTINATION_HOST_ISOLATED(IcmpType.DESTINATION_UNREACHABLE, 8),
		DESTINATION_NETWORK_ADMIN_PROHIBITED(IcmpType.DESTINATION_UNREACHABLE, 9),
		DESTINATION_HOST_ADMIN_PROHIBITED(IcmpType.DESTINATION_UNREACHABLE, 10),
		DESTINATION_NETWORK_UNREACHABLE_FOR_SERVICE(
		    IcmpType.DESTINATION_UNREACHABLE, 11),
		DESTINATION_HOST_UNREACHABLE_FOR_SERVICE(
		    IcmpType.DESTINATION_UNREACHABLE, 12),

		REDIRECT_NETWORK(IcmpType.REDIRECT, 0),
		REDIRECT_HOST(IcmpType.REDIRECT, 1),
		REDIRECT_SERVICE_AND_NETWORK(IcmpType.REDIRECT, 2),
		REDIRECT_SERVICE_AND_HOST(IcmpType.REDIRECT, 3),

		TIME_EXCEEDED_IN_TRANSIT(IcmpType.TIME_EXCEEDED, 1),
		TIME_EXCEEDED_DURING_FRAG_REASSEMBLY(IcmpType.TIME_EXCEEDED, 1),

		PARAMETER_PROBLEM_WITH_DATAGRAM(IcmpType.PARAM_PROBLEM, 0),
		PARAMETER_PROBLEM_MISSING_OPTION(IcmpType.PARAM_PROBLEM, 1), ;

		private final IcmpType type;

		private final int code;

		private final String description;

		private IcmpCode(IcmpType type, int code) {
			this.type = type;
			this.code = code;
			this.description = name().toString().toLowerCase().replace('_', ' ');
		}

		private IcmpCode(IcmpType type, int code, String description) {
			this.type = type;
			this.code = code;
			this.description = description;

		}

		public static IcmpCode valueOf(int type, int code) {
			for (IcmpCode t : values()) {
				if (t.type.id == type && t.code == code) {
					return t;
				}
			}

			return null;
		}

		public static String toString(int type, int code) {
			for (IcmpCode t : values()) {
				if (t.type.id == type && t.code == code) {
					return t.description;
				}
			}

			return null;
		}

		public final IcmpType getType() {
			return this.type;
		}

		public final int getCode() {
			return this.code;
		}

		public final String getDescription() {
			return this.description;
		}
	}

	/**
	 * A table of IcmpTypes and their names
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum IcmpType {
		DESTINATION_UNREACHABLE(3, "destination unreachable"),
		ECHO_REPLY(0, "echo reply"),
		ECHO_REQUEST(8, "echo request"),
		INFO_REQUEST(15, "info request"),
		INFO_RESPONSE(16, "info response"),
		PARAM_PROBLEM(12, "parameter problem"),
		REDIRECT(5, "redirect"),
		SOURCE_QUENCH(4, "source quench"),
		TIME_EXCEEDED(11, "time exceeded"),
		TIMESTAMP_REQUEST(13, "timestamp request"),
		TIMESTAMP_RESPONSE(14, "timestamp response"),

		;
		public static String toString(int id) {
			for (IcmpType t : values()) {
				if (t.id == id) {
					return t.description;
				}
			}

			return null;
		}

		/**
		 * @param type
		 * @return
		 */
		public static IcmpType valueOf(int type) {
			for (IcmpType t : values()) {
				if (t.id == type) {
					return t;
				}
			}

			return null;
		}

		private final String description;

		public final int id;

		private IcmpType(int id) {
			this.id = id;
			this.description = name().toLowerCase().replace('_', ' ');
		}

		private IcmpType(int id, String description) {
			this.id = id;
			this.description = description;

		}

		public final String getDescription() {
			return this.description;
		}

		public final int getId() {
			return this.id;
		}

	}

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public static final int ID = JProtocol.ICMP_ID;

	public static final int LENGTH = 8;

	/**
	 * Field objects for JFormatter
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] X_FIELDS =
	    {
	        new JField("type", "type", new JStaticField<Icmp, Integer>(0, 1) {

		        public Integer value(Icmp header) {
			        return header.type();
		        }

		        @Override
		        public String valueDescription(Icmp header) {
			        final String s = IcmpType.toString(header.type());
			        if (s == null) {
				        return super.valueDescription(header);
			        } else {
				        return s;
			        }
		        }

	        }),
	        new JField("code", "code", new JStaticField<Icmp, Integer>(0, 1) {

		        public Integer value(Icmp header) {
			        return header.code();
		        }

		        @Override
		        public String valueDescription(Icmp header) {
			        final String s = IcmpCode.toString(header.type(), header.code());
			        if (s == null) {
				        return super.valueDescription(header);
			        } else {
				        return s;
			        }
		        }
	        }),
	        new JField(Style.INT_HEX, "checksum", "crc",
	            new JStaticField<Icmp, Integer>(0, 1) {

		            public Integer value(Icmp header) {
			            return header.checksum();
		            }
	            }), };

	public final static JHeader[] X_HEADERS = {
	    new Icmp.EchoRequest(),
	    new Icmp.EchoReply(),
	    new Icmp.DestinationUnreachable(),
	    new Icmp.Redirect(),
	    new Icmp.ParamProblem(),
	    new Icmp.SourceQuench() };

	/**
	 * @param id
	 */
	public Icmp() {
		super(ID, X_FIELDS, "icmp", "icmp", X_HEADERS);
		order(BYTE_ORDER);
	}

	public int checksum() {
		return super.getUShort(2);
	}

	public int code() {
		return super.getUByte(1);
	}

	public IcmpCode codeEnum() {
		return IcmpCode.valueOf(type(), code());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JHeaderMap#decodeUniqueSubHeaders()
	 */
	@Override
	protected void decodeHeader() {
		final int id = type();
		optionsOffsets[id] = 4;
		optionsBitmap = (1 << id);
		optionsLength[id] = getLength() - 4;

	}

	public int type() {
		return super.getUByte(0);
	}

	public IcmpType typeEnum() {
		return IcmpType.valueOf(type());
	}

}
