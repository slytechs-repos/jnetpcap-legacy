/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.protocol.voip;

import org.jnetpcap.packet.AbstractMessageHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header()
public class Sip
    extends
    AbstractMessageHeader {

	public enum Code {
		Address_Incomplete(484, "Address Incomplete"),
		Alternative_Service(380, "Alternative Service"),
		Ambiguous(485, "Ambiguous"),
		Bad_Extension(420, "Bad Extension"),
		Bad_Gateway(502, "Bad Gateway"),
		Bad_Request(400, "Bad Request"),
		Busy_Everywhere(600, "Busy Everywhere"),
		Busy_Here(486, "Busy Here"),
		Call_Leg_Transaction_Does_Not_Exist(
		    481, "Call Leg/Transaction Does Not Exist"),
		Decline(603, "Decline"),
		Does_not_exist_anywhere(604, "Does not exist anywhere"),
		Extension_Required(421, "Extension Required"),
		Forbidden(403, "Forbidden"),
		Gone(410, "Gone"),
		Internal_Server_Error(500, "Internal Server Error"),
		Interval_Too_Brief(423, "Interval Too Brief"),
		Loop_Detected(482, "Loop Detected"),
		Message_Too_Large(513, "Message Too Large"),
		Method_Not_Allowed(405, "Method Not Allowed"),
		Moved_Permanently(301, "Moved Permanently"),
		Moved_Temporarily(302, "Moved Temporarily"),
		MULTIPLE_CHOICES(300, "Multiple Choices"),
		Not_Acceptable_Here(488, "Not Acceptable Here"),
		Not_Acceptable400(406, "Not Acceptable"),
		Not_Acceptable600(606, "Not Acceptable"),
		Not_Found(404, "Not Found"),
		Not_Implemented(501, "Not Implemented"),
		OK(200, "OK"),
		Payment_Required(402, "Payment Required"),
		Proxy_Authentication_Required(407, "Proxy Authentication Required"),
		Request_Entity_Too_Large(413, "Request Entity Too Large"),
		Request_Pending(491, "Request Pending"),
		Request_Terminated(487, "Request Terminated"),
		Request_Timeout(408, "Request Timeout"),
		Request_URI_Too_Large(414, "Request-URI Too Large"),
		Server_Time_out(504, "Server Time-out"),
		Service_Unavailable(503, "Service Unavailable"),
		SIP_Version_not_supported(505, "SIP Version not supported"),
		Temporarily_not_available(480, "Temporarily not available"),
		Too_Many_Hops(483, "Too Many Hops"),
		Unauthorized(401, "Unauthorized"),
		Undecipherable(493, "Undecipherable"),
		Unsupported_Media_Type(415, "Unsupported Media Type"),
		Unsupported_URI_Scheme(416, "Unsupported URI Scheme"),
		Use_Proxy(305, "Use Proxy");

		private final int code;

		private final String description;

		private Code(final int code, final String description) {
			this.code = code;
			this.description = description;

		}

		public final int getCode() {
			return this.code;
		}

		public final String getDescription() {
			return this.description;
		}

		public Code valueOf(final int code) {
			for (final Code c : values()) {
				if (c.code == code) {
					return c;
				}
			}

			return null;
		}

		public Code valueOfUsingCode(final String code) {
			return valueOf(Integer.parseInt(code));
		}

	}

	public enum ContentType {
		OTHER,
		PKCS7_MIME("application/pkcs7-mime"),
		PKCS7_SIGNATURE("application/pkcs7-signature"),
		SPD("application/SPD"), ;

		public static ContentType parseContentType(final String type) {
			if (type == null) {
				return OTHER;
			}

			for (final ContentType t : values()) {
				if (t.name().equalsIgnoreCase(type)) {
					return t;
				}

				for (final String m : t.magic) {
					if (type.startsWith(m)) {
						return t;
					}
				}
			}

			return OTHER;
		}

		private final String[] magic;

		private ContentType(final String... magic) {
			this.magic = magic;
		}
	}

	@Field
	public enum Fields {
		Accept,
		Accept_Encoding,
		Accept_Language,
		Alert_Info,
		Allow,
		Authentication_Info,
		Authorization,
		Call_ID,
		Call_Info,
		Contact,
		Content_Disposition,
		Content_Encoding,
		Content_Language,
		Content_Length,
		Content_Type,
		CSeq,
		Date,
		Error_Info,
		Expires,
		From,
		In_Reply_To,
		Max_Forwards,
		MIME_Version,
		Min_Expires,
		Organization,
		Priority,
		Proxy_Authenticate,
		Proxy_Authorization,
		Proxy_Require,
		Record_Route,
		Reply_To,
		Require,
		Retry_After,
		Route,
		Server,
		Subject,
		Supported,
		Timestamp,
		To,
		Unsupported,
		User_Agent,
		Via,
		Warning,
		WWW_Authenticate

	}

	@Field
	public enum Request {
		RequestMethod,
		RequestUrl,
		RequestVersion,
		User_Agent,

	}

	@Field
	public enum Response {
		RequestUrl,
		RequestVersion,
		ResponseCode,
		ResponseCodeMsg,
	}

	/**
	 * Constant numerial ID for this protocol's header
	 */
	public static int ID = JProtocol.SIP_ID;

	public String contentType() {
		return fieldValue(Fields.Content_Type);
	}

	public ContentType contentTypeEnum() {
		return ContentType.parseContentType(contentType());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.AbstractMessageHeader#decodeFirstLine(java.lang.String)
	 */
	@Override
	protected void decodeFirstLine(final String line) {
		final String[] c = line.split(" ");
		if (c.length < 3) {
			return; // Can't parse it
		}

		if (c[0].startsWith("SIP")) {
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

	public String fieldValue(final Sip.Fields field) {
		return super.fieldValue(String.class, field);
	}

	public String fieldValue(final Sip.Request field) {
		return super.fieldValue(String.class, field);
	}

	public String fieldValue(final Sip.Response field) {
		return super.fieldValue(String.class, field);
	}

	public boolean hasContent() {
		return hasField(Fields.Content_Type) || hasField(Fields.Content_Type);
	}

	/**
	 * @return
	 */
	public boolean hasContentType() {
		return hasField(Fields.Content_Type);
	}

	public boolean hasField(Fields field) {
		return super.hasField(field);
	}

	/**
	 * Gets the raw header instead of reconstructing it.
	 * 
	 * @return original raw header
	 */
	public String header() {
		return super.rawHeader;
	}

	public boolean isResponse() {
		return getMessageType() == MessageType.RESPONSE;
	}

	/**
	 * @return
	 */
	public int contentLength() {
		if (hasField(Fields.Content_Length)) {
			return Integer.parseInt(super.fieldValue(String.class,
			    Fields.Content_Length));
		} else {
			return 0;
		}
	}

}
