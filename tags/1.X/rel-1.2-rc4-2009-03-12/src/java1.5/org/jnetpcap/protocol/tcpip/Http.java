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
package org.jnetpcap.protocol.tcpip;

import org.jnetpcap.packet.AbstractMessageHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(suite=ProtocolSuite.TCP_IP)
public class Http
    extends AbstractMessageHeader {

	@Bind(to = Tcp.class, intValue = {
	    80,
	    8080 })
	public static boolean bindToTcp(JPacket packet, Tcp tcp) {
		return tcp.destination() == 80 || tcp.source() == 80
		    || tcp.destination() == 8080 || tcp.source() == 8080;
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
		Authorization,
		Cache_Control,
		Connection,
		Cookie,
		Date,
		Host,
		If_Modified_Since,
		If_None_Match,
		Referrer,
		User_Agent,

		RequestVersion,
		RequestMethod,
		RequestUrl,
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
		Content_Encoding,
		Content_Length,
		Content_Location,
		Content_Disposition,
		Content_MD5,
		Content_Range,
		Content_Type,

		RequestVersion,
		ResponseCode,
		ResponseCodeMsg,
		RequestUrl,
	}

	public enum ContentType {
		JPEG("image/jpeg"),
		GIF("image/gif"),
		PNG("image/png"),
		HTML("text/html"), ;

		private final String[] magic;

		private ContentType(String... magic) {
			this.magic = magic;
		}

		public static ContentType parseContentType(String type) {
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

			return null;
		}
	}

	public boolean hasField(Request field) {
		return super.hasField(field);
	}

	public String fieldValue(Request field) {
		return super.fieldValue(String.class, field);
	}

	public boolean hasField(Response field) {
		return super.hasField(field);
	}

	public String fieldValue(Response field) {
		return super.fieldValue(String.class, field);
	}

	@Override
	protected void decodeFirstLine(String line) {
		// System.out.printf("#%d Http::decodeFirstLine line=%s\n", getPacket()
		// .getFrameNumber(), line);
		String[] c = line.split(" ");
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

	/**
	 * @return
	 */
	public boolean hasContentType() {
		return hasField(Response.Content_Type);
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
	 * @return
	 */
	public boolean isResponse() {
		return getMessageType() == MessageType.RESPONSE;
	}

	/**
	 * @return
	 */
	public boolean hasContent() {
		return hasField(Response.Content_Type);
	}
}
