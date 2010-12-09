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
package org.jnetpcap.protocol.voip;

import org.jnetpcap.packet.AbstractMessageHeader;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Class Sip.
 */
@Header()
public class Sip
    extends
    AbstractMessageHeader {

	/**
	 * The Enum Code.
	 */
	public enum Code {
		
		/** The Address_ incomplete. */
		Address_Incomplete(484, "Address Incomplete"),

		/** The Alternative_ service. */
		Alternative_Service(380, "Alternative Service"),

		/** The Ambiguous. */
		Ambiguous(485, "Ambiguous"),

		/** The Bad_ extension. */
		Bad_Extension(420, "Bad Extension"),

		/** The Bad_ gateway. */
		Bad_Gateway(502, "Bad Gateway"),

		/** The Bad_ request. */
		Bad_Request(400, "Bad Request"),

		/** The Busy_ everywhere. */
		Busy_Everywhere(600, "Busy Everywhere"),

		/** The Busy_ here. */
		Busy_Here(486, "Busy Here"),

		/** The Call_ leg_ transaction_ does_ not_ exist. */
		Call_Leg_Transaction_Does_Not_Exist(
		    481, "Call Leg/Transaction Does Not Exist"),

		/** The Decline. */
		Decline(603, "Decline"),

		/** The Does_not_exist_anywhere. */
		Does_not_exist_anywhere(604, "Does not exist anywhere"),

		/** The Extension_ required. */
		Extension_Required(421, "Extension Required"),

		/** The Forbidden. */
		Forbidden(403, "Forbidden"),

		/** The Gone. */
		Gone(410, "Gone"),

		/** The Internal_ server_ error. */
		Internal_Server_Error(500, "Internal Server Error"),

		/** The Interval_ too_ brief. */
		Interval_Too_Brief(423, "Interval Too Brief"),

		/** The Loop_ detected. */
		Loop_Detected(482, "Loop Detected"),

		/** The Message_ too_ large. */
		Message_Too_Large(513, "Message Too Large"),

		/** The Method_ not_ allowed. */
		Method_Not_Allowed(405, "Method Not Allowed"),

		/** The Moved_ permanently. */
		Moved_Permanently(301, "Moved Permanently"),

		/** The Moved_ temporarily. */
		Moved_Temporarily(302, "Moved Temporarily"),

		/** The MULTIPL e_ choices. */
		MULTIPLE_CHOICES(300, "Multiple Choices"),

		/** The Not_ acceptable_ here. */
		Not_Acceptable_Here(488, "Not Acceptable Here"),
		
		/** The Not_ acceptable400. */
		Not_Acceptable400(406, "Not Acceptable"),

		/** The Not_ acceptable600. */
		Not_Acceptable600(606, "Not Acceptable"),

		/** The Not_ found. */
		Not_Found(404, "Not Found"),

		/** The Not_ implemented. */
		Not_Implemented(501, "Not Implemented"),

		/** The OK. */
		OK(200, "OK"),

		/** The Payment_ required. */
		Payment_Required(402, "Payment Required"),

		/** The Proxy_ authentication_ required. */
		Proxy_Authentication_Required(407, "Proxy Authentication Required"),

		/** The Request_ entity_ too_ large. */
		Request_Entity_Too_Large(413, "Request Entity Too Large"),
		
		/** The Request_ pending. */
		Request_Pending(491, "Request Pending"),
		
		/** The Request_ terminated. */
		Request_Terminated(487, "Request Terminated"),

		/** The Request_ timeout. */
		Request_Timeout(408, "Request Timeout"),

		/** The Request_ ur i_ too_ large. */
		Request_URI_Too_Large(414, "Request-URI Too Large"),

		/** The Server_ time_out. */
		Server_Time_out(504, "Server Time-out"),

		/** The Service_ unavailable. */
		Service_Unavailable(503, "Service Unavailable"),

		/** The SI p_ version_not_supported. */
		SIP_Version_not_supported(505, "SIP Version not supported"),

		/** The Temporarily_not_available. */
		Temporarily_not_available(480, "Temporarily not available"),

		/** The Too_ many_ hops. */
		Too_Many_Hops(483, "Too Many Hops"),

		/** The Unauthorized. */
		Unauthorized(401, "Unauthorized"),

		/** The Undecipherable. */
		Undecipherable(493, "Undecipherable"),
		
		/** The Unsupported_ media_ type. */
		Unsupported_Media_Type(415, "Unsupported Media Type"),

		/** The Unsupported_ ur i_ scheme. */
		Unsupported_URI_Scheme(416, "Unsupported URI Scheme"),

		/** The Use_ proxy. */
		Use_Proxy(305, "Use Proxy");

		/** The code. */
		private final int code;

		/** The description. */
		private final String description;

		/**
		 * Instantiates a new code.
		 * 
		 * @param code
		 *          the code
		 * @param description
		 *          the description
		 */
		private Code(final int code, final String description) {
			this.code = code;
			this.description = description;

		}

		/**
		 * Gets the code.
		 * 
		 * @return the code
		 */
		public final int getCode() {
			return this.code;
		}

		/**
		 * Gets the description.
		 * 
		 * @return the description
		 */
		public final String getDescription() {
			return this.description;
		}

		/**
		 * Value of.
		 * 
		 * @param code
		 *          the code
		 * @return the code
		 */
		public Code valueOf(final int code) {
			for (final Code c : values()) {
				if (c.code == code) {
					return c;
				}
			}

			return null;
		}

		/**
		 * Value of using code.
		 * 
		 * @param code
		 *          the code
		 * @return the code
		 */
		public Code valueOfUsingCode(final String code) {
			return valueOf(Integer.parseInt(code));
		}

	}

	/**
	 * The Enum ContentType.
	 */
	public enum ContentType {
		
		/** The OTHER. */
		OTHER,
		
		/** The PKC s7_ mime. */
		PKCS7_MIME("application/pkcs7-mime"),

		/** The PKC s7_ signature. */
		PKCS7_SIGNATURE("application/pkcs7-signature"),

		/** The SPD. */
		SPD("application/SPD"), ;

		/**
		 * Parses the content type.
		 * 
		 * @param type
		 *          the type
		 * @return the content type
		 */
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

		/** The magic. */
		private final String[] magic;

		/**
		 * Instantiates a new content type.
		 * 
		 * @param magic
		 *          the magic
		 */
		private ContentType(final String... magic) {
			this.magic = magic;
		}
	}

	/**
	 * The Enum Fields.
	 */
	@Field
	public enum Fields {
		
		/** The Accept. */
		Accept,

		/** The Accept_ encoding. */
		Accept_Encoding,

		/** The Accept_ language. */
		Accept_Language,

		/** The Alert_ info. */
		Alert_Info,

		/** The Allow. */
		Allow,
		
		/** The Authentication_ info. */
		Authentication_Info,

		/** The Authorization. */
		Authorization,

		/** The Call_ id. */
		Call_ID,

		/** The Call_ info. */
		Call_Info,

		/** The Contact. */
		Contact,
		
		/** The Content_ disposition. */
		Content_Disposition,

		/** The Content_ encoding. */
		Content_Encoding,

		/** The Content_ language. */
		Content_Language,

		/** The Content_ length. */
		Content_Length,

		/** The Content_ type. */
		Content_Type,

		/** The C seq. */
		CSeq,
		
		/** The Date. */
		Date,
		
		/** The Error_ info. */
		Error_Info,
		
		/** The Expires. */
		Expires,
		
		/** The From. */
		From,
		
		/** The In_ reply_ to. */
		In_Reply_To,
		
		/** The Max_ forwards. */
		Max_Forwards,
		
		/** The MIM e_ version. */
		MIME_Version,

		/** The Min_ expires. */
		Min_Expires,
		
		/** The Organization. */
		Organization,
		
		/** The Priority. */
		Priority,
		
		/** The Proxy_ authenticate. */
		Proxy_Authenticate,
		
		/** The Proxy_ authorization. */
		Proxy_Authorization,
		
		/** The Proxy_ require. */
		Proxy_Require,
		
		/** The Record_ route. */
		Record_Route,
		
		/** The Reply_ to. */
		Reply_To,
		
		/** The Require. */
		Require,
		
		/** The Retry_ after. */
		Retry_After,
		
		/** The Route. */
		Route,
		
		/** The Server. */
		Server,
		
		/** The Subject. */
		Subject,
		
		/** The Supported. */
		Supported,
		
		/** The Timestamp. */
		Timestamp,
		
		/** The To. */
		To,
		
		/** The Unsupported. */
		Unsupported,
		
		/** The User_ agent. */
		User_Agent,
		
		/** The Via. */
		Via,
		
		/** The Warning. */
		Warning,

		/** The WW w_ authenticate. */
		WWW_Authenticate

	}

	/**
	 * The Enum Request.
	 */
	@Field
	public enum Request {
		
		/** The Request method. */
		RequestMethod,
		
		/** The Request url. */
		RequestUrl,
		
		/** The Request version. */
		RequestVersion,

		/** The User_ agent. */
		User_Agent,

	}

	/**
	 * The Enum Response.
	 */
	@Field
	public enum Response {
		
		/** The Request url. */
		RequestUrl,
		
		/** The Request version. */
		RequestVersion,
		
		/** The Response code. */
		ResponseCode,
		
		/** The Response code msg. */
		ResponseCodeMsg,
	}

	/** The ID. */
	public static int ID = JProtocol.SIP_ID;

	/**
	 * Content length.
	 * 
	 * @return the int
	 */
	public int contentLength() {
		if (hasField(Fields.Content_Length)) {
			return Integer.parseInt(super.fieldValue(String.class,
			    Fields.Content_Length));
		} else {
			return 0;
		}
	}

	/**
	 * Content type.
	 * 
	 * @return the string
	 */
	public String contentType() {
		return fieldValue(Fields.Content_Type);
	}

	/**
	 * Content type enum.
	 * 
	 * @return the content type
	 */
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

	/**
	 * Field value.
	 * 
	 * @param field
	 *          the field
	 * @return the string
	 */
	public String fieldValue(final Sip.Fields field) {
		return super.fieldValue(String.class, field);
	}

	/**
	 * Field value.
	 * 
	 * @param field
	 *          the field
	 * @return the string
	 */
	public String fieldValue(final Sip.Request field) {
		return super.fieldValue(String.class, field);
	}

	/**
	 * Field value.
	 * 
	 * @param field
	 *          the field
	 * @return the string
	 */
	public String fieldValue(final Sip.Response field) {
		return super.fieldValue(String.class, field);
	}

	/**
	 * Checks for content.
	 * 
	 * @return true, if successful
	 */
	public boolean hasContent() {
		return hasField(Fields.Content_Type) || hasField(Fields.Content_Type);
	}

	/**
	 * Checks for content type.
	 * 
	 * @return true, if successful
	 */
	public boolean hasContentType() {
		return hasField(Fields.Content_Type);
	}

	/**
	 * Checks for field.
	 * 
	 * @param field
	 *          the field
	 * @return true, if successful
	 */
	public boolean hasField(final Fields field) {
		return super.hasField(field);
	}

	/**
	 * Header.
	 * 
	 * @return the string
	 */
	public String header() {
		return super.rawHeader;
	}

	/**
	 * Checks if is response.
	 * 
	 * @return true, if is response
	 */
	public boolean isResponse() {
		return getMessageType() == MessageType.RESPONSE;
	}

}
