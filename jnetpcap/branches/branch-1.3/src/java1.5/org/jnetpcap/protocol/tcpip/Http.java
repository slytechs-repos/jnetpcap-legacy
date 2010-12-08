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

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.AbstractMessageHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.JProtocol;

/**
 * Hyper Text Transfer Protocol header definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(suite = ProtocolSuite.TCP_IP)
public class Http
    extends
    AbstractMessageHeader {

	/**
	 * Constant numerical ID assigned to this protocol
	 */
	public final static int ID = JProtocol.HTTP_ID;

	/**
	 * Http content type table.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum ContentType {
		GIF("image/gif"),
		HTML("text/html"),
		JPEG("image/jpeg"),
		PNG("image/png"),
		OTHER, ;

		public static ContentType parseContentType(String type) {
			if (type == null) {
				return OTHER;
			}

			for (ContentType t : values()) {
				if (t.name().equalsIgnoreCase(type)) {
					return t;
				}

				for (String m : t.magic) {
					if (type.startsWith(m)) {
						return t;
					}
				}
			}

			return OTHER;
		}

		private final String[] magic;

		private ContentType(String... magic) {
			this.magic = magic;
		}
	}

	/**
	 * HTTP Request fields
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Field
	public enum Request {
		Accept,
		Accept_Charset,
		Accept_Encoding,
		Accept_Ranges,
		Accept_Language,
		
		UA_CPU,
		Proxy_Connection,
		
		Authorization,
		Cache_Control,
		Connection,
		Cookie,
		Date,
		Host,
		If_Modified_Since,
		If_None_Match,
		Referer,
		RequestMethod,

		RequestUrl,
		RequestVersion,
		User_Agent,

		Content_Length,
		Content_Type,
	}

	/**
	 * HTTP Response fields
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Field
	public enum Response {
		Accept_Ranges,
		Age,
		Allow,
		Cache_Control,
		Content_Disposition,
		Content_Encoding,
		Content_Length,
		Content_Location,
		Content_MD5,
		Content_Range,
		Content_Type,
		
		Expires,
		Server,
		Set_Cookie,

		RequestUrl,
		RequestVersion,
		ResponseCode,
		ResponseCodeMsg,
	}

	/**
	 * @return
	 */
	public String contentType() {
		return fieldValue(Response.Content_Type);
	}

	public ContentType contentTypeEnum() {
		return ContentType.parseContentType(contentType());
	}

	/**
	 * A http chunk that has been encoded during transfer as "Transfer-Encoding:
	 * chuncked".
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class Chunk
	    extends
	    JBuffer {

		/**
		 * @param type
		 */
		public Chunk(Type type) {
			super(type);
		}

	}

	public boolean hasChuncks() {
		return false;
	}

	public Chunk[] chunks() {
		return new Chunk[0];
	}

	@Override
	protected void decodeFirstLine(String line) {
		// System.out.printf("#%d Http::decodeFirstLine line=%s\n", getPacket()
		// .getFrameNumber(), line);
		String[] c = line.split(" ");
		if (c.length < 3) {
			return; // Can't parse it
		}

		if (c[0].startsWith("HTTP")) {
			super.setMessageType(MessageType.RESPONSE);

			super.addField(Response.RequestVersion, c[0], line.indexOf(c[0]));
			super.addField(Response.ResponseCode, c[1], line.indexOf(c[1]));
			super.addField(Response.ResponseCodeMsg, c[2], line.indexOf(c[2]));

		} else {
			super.setMessageType(MessageType.REQUEST);

			super.addField(Request.RequestMethod, c[0], line.indexOf(c[0]));
			super.addField(Request.RequestUrl, c[1], line.indexOf(c[1]));
			super.addField(Request.RequestVersion, c[2], line.indexOf(c[2]));
		}
	}

	public String fieldValue(Request field) {
		return super.fieldValue(String.class, field);
	}

	public String fieldValue(Response field) {
		return super.fieldValue(String.class, field);
	}

	/**
	 * @return
	 */
	public boolean hasContent() {
		return hasField(Response.Content_Type) || hasField(Request.Content_Type);
	}

	/**
	 * @return
	 */
	public boolean hasContentType() {
		return hasField(Response.Content_Type);
	}

	public boolean hasField(Request field) {
		return super.hasField(field);
	}

	public boolean hasField(Response field) {
		return super.hasField(field);
	}

	/**
	 * @return
	 */
	public boolean isResponse() {
		return getMessageType() == MessageType.RESPONSE;
	}

	/**
	 * Gets the raw header instead of reconstructing it.
	 * 
	 * @return original raw header
	 */
	public String header() {
		return super.rawHeader;
	}
}
