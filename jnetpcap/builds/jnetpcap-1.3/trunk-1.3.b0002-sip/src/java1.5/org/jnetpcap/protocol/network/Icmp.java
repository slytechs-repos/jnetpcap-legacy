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
package org.jnetpcap.protocol.network;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeaderMap;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.JProtocol;

/**
 * ICMP header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
public class Icmp
    extends JHeaderMap<Icmp> {

	/**
	 * ICMP Destination Unreachable header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(length = 4, id = IcmpType.DESTINATION_UNREACHABLE_ID, nicname = "unreach")
	public static class DestinationUnreachable
	    extends Reserved {
	}

	/**
	 * ICMP Echo header (ping) baseclass definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static abstract class Echo
	    extends JSubHeader<Icmp> {

		@Field(offset = 0, length = 16, format = "%x")
		public int id() {
			return super.getUShort(0);
		}

		@Field(offset = 16, length = 16, format = "%x")
		public int sequence() {
			return super.getUShort(2);
		}
	};

	/**
	 * ICMP Echo Reply header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = IcmpType.ECHO_REPLY_ID, length = 4, nicname = "reply")
	public static class EchoReply
	    extends Echo {

	}

	/**
	 * ICMP Echo Request header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(id = IcmpType.ECHO_REQUEST_ID, length = 4, nicname = "request")
	public static class EchoRequest
	    extends Echo {

	}

	/**
	 * A table of Icmp sub-codes per Icmp type
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum IcmpCode {
		DESTINATION_HOST_ADMIN_PROHIBITED(IcmpType.DESTINATION_UNREACHABLE, 10),
		DESTINATION_HOST_ISOLATED(IcmpType.DESTINATION_UNREACHABLE, 8),
		DESTINATION_HOST_UNKNOWN(IcmpType.DESTINATION_UNREACHABLE, 7),
		DESTINATION_HOST_UNREACHABLE_FOR_SERVICE(
		    IcmpType.DESTINATION_UNREACHABLE, 12),
		DESTINATION_NETWORK_ADMIN_PROHIBITED(IcmpType.DESTINATION_UNREACHABLE, 9),
		DESTINATION_NETWORK_REDIRECT(IcmpType.DESTINATION_UNREACHABLE, 0),
		DESTINATION_NETWORK_UNREACHABLE(IcmpType.DESTINATION_UNREACHABLE, 6),
		DESTINATION_NETWORK_UNREACHABLE_FOR_SERVICE(
		    IcmpType.DESTINATION_UNREACHABLE, 11),
		DESTINATION_NO_FRAG(IcmpType.DESTINATION_UNREACHABLE, 4),
		DESTINATION_PORT_UNREACHABLE(IcmpType.DESTINATION_UNREACHABLE, 3),
		DESTINATION_PROTOCOL_UNREACHABLE(IcmpType.DESTINATION_UNREACHABLE, 1),
		DESTINATION_SOURCE_ROUTE(IcmpType.DESTINATION_UNREACHABLE, 5),

		PARAMETER_PROBLEM_MISSING_OPTION(IcmpType.PARAM_PROBLEM, 1),
		PARAMETER_PROBLEM_WITH_DATAGRAM(IcmpType.PARAM_PROBLEM, 0),
		REDIRECT_HOST(IcmpType.REDIRECT, 1),
		REDIRECT_NETWORK(IcmpType.REDIRECT, 0),

		REDIRECT_SERVICE_AND_HOST(IcmpType.REDIRECT, 3),
		REDIRECT_SERVICE_AND_NETWORK(IcmpType.REDIRECT, 2),

		TIME_EXCEEDED_DURING_FRAG_REASSEMBLY(IcmpType.TIME_EXCEEDED, 1),
		TIME_EXCEEDED_IN_TRANSIT(IcmpType.TIME_EXCEEDED, 1), ;

		public static String toString(int type, int code) {
			for (IcmpCode t : values()) {
				if (t.type.id == type && t.code == code) {
					return t.description;
				}
			}

			return null;
		}

		public static IcmpCode valueOf(int type, int code) {
			for (IcmpCode t : values()) {
				if (t.type.id == type && t.code == code) {
					return t;
				}
			}

			return null;
		}

		private final int code;

		private final String description;

		private final IcmpType type;

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

		public final int getCode() {
			return this.code;
		}

		public final String getDescription() {
			return this.description;
		}

		public final IcmpType getType() {
			return this.type;
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

		public final static int DESTINATION_UNREACHABLE_ID = 3;

		public final static int ECHO_REPLY_ID = 0;

		public final static int ECHO_REQUEST_ID = 8;

		public final static int INFO_REQUEST_ID = 15;

		public final static int INFO_RESPONSE_ID = 16;

		public final static int PARAM_PROBLEM_ID = 12;

		public final static int REDIRECT_ID = 5;

		public final static int SOURCE_QUENCH_ID = 4;

		public final static int TIME_EXCEEDED_ID = 11;

		public final static int TIMESTAMP_REQUEST_ID = 13;

		public final static int TIMESTAMP_RESPONSE_ID = 14;

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

	/**
	 * ICMP Paramater Protoblem header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(length = 4, id = IcmpType.PARAM_PROBLEM_ID)
	public static class ParamProblem
	    extends JSubHeader<Icmp> {

		@Field(offset = 0, length = 8)
		public int pointer() {
			return getUByte(0);
		}

		@Field(offset = 8, length = 24)
		public int reserved() {
			return (int) (getUInt(0) & 0x00FFFFFFL);
		}
	}

	/**
	 * ICMP Redirect header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(length = 4, id = IcmpType.REDIRECT_ID)
	public static class Redirect
	    extends JSubHeader<Icmp> {

		public byte[] gateway() {
			return getByteArray(0, 4);
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

		public long reserved() {
			return getUInt(0);
		}
	}

	/**
	 * ICMP Source Quence header definition
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header(length = 4, id = IcmpType.SOURCE_QUENCH_ID)
	public static class SourceQuench
	    extends Reserved {

	}

	public static final int ID = JProtocol.ICMP_ID;

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		switch (buffer.getUByte(offset)) {
			case 0: // EchoReply
			case 8: // EchoRequest
				return buffer.size() - offset - 4;

			case 4: // SourceQuench
			case 5: // Redirect
			case 11: // Timestamp
			default:
				return 4;
		}
	}

	@Field(offset = 2 * 8, length = 16, format = "%x")
	public int checksum() {
		return super.getUShort(2);
	}

	@Field(offset = 1 * 8, length = 8, format = "%x")
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

	@Field(offset = 0 * 8, length = 8, format = "%x")
	public int type() {
		return super.getUByte(0);
	}

	@Dynamic(Field.Property.DESCRIPTION)
	public String typeDescription() {
		return IcmpType.valueOf(type()).getDescription();
	}

	public IcmpType typeEnum() {
		return IcmpType.valueOf(type());
	}

}
