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

import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldRuntime;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.FieldRuntime.FieldFunction;
import org.jnetpcap.packet.header.Tcp;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(nicname = "Http")
public class Http
    extends JHeader {

	private final static char[] HTTP_HEADER_DELIMITER = {
	    '\r',
	    '\n',
	    '\r',
	    '\n' };

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		return buffer.findUTF8String(offset, HTTP_HEADER_DELIMITER);
	}

	/**
	 * Class which describes a single field within the Http header.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class Entry {
		private String name;

		private String value;

		private int offset;

		private int length;

		/**
		 * @param name
		 * @param value
		 * @param offset
		 * @param length
		 */
		public Entry(String name, String value, int offset, int length) {
			this.name = name;
			this.value = value;
			this.offset = offset;
			this.length = length;
		}

		public final String getName() {
			return this.name;
		}

		public final String getValue() {
			return this.value;
		}

		public final int getOffset() {
			return this.offset;
		}

		public final int getLength() {
			return this.length;
		}

		public String toString() {
			StringBuilder b = new StringBuilder();
			b.append('[').append(offset).append('/').append(length).append(']');
			b.append(name).append('=').append(value);

			return b.toString();
		}
	}

	/**
	 * Default binding for Http protocol. Additional bindings can be registered
	 * for other port numbers.
	 * 
	 * @param packet
	 * @param tcp
	 * @return
	 */
	@Bind(to = Tcp.class)
	public static boolean isBound(JPacket packet, Tcp tcp) {
		final int sp = tcp.source();
		final int dp = tcp.destination();

		return sp == 80 || dp == 80 || sp == 8080 || dp == 8080;
	}

	private final StringBuilder buf = new StringBuilder(1024);

	private final Map<String, Entry> mapByName = new HashMap<String, Entry>();

	private String requestMethod;

	private String requestUrl;

	private String requestVersion;

	private int responseCode;

	private String responseCodeMessage;

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasAccept() {
		return mapByName.containsKey("Accept");
	}

	@Field(offset = 5, length = 0, format = "%s", display = "Accept")
	public String accept() {
		return mapByName.get("Accept").getValue();
	}

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasAcceptCharset() {
		return mapByName.containsKey("Accept-Charset");
	}

	@Field(offset = 7, length = 0, format = "%s", display = "Accept-Charset")
	public String acceptCharset() {
		return mapByName.get("Accept-Charset").getValue();
	}

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasAcceptEncoding() {
		return mapByName.containsKey("Accept-Encoding");
	}

	@Field(offset = 8, length = 0, format = "%s", display = "Accept-Encoding")
	public String acceptEncoding() {
		return mapByName.get("Accept-Encoding").getValue();
	}

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasAcceptLanguage() {
		return mapByName.containsKey("Accept-Language");
	}

	@Field(offset = 6, length = 0, format = "%s", display = "Accept-Language")
	public String acceptLanguage() {
		return mapByName.get("Accept-Language").getValue();
	}

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasConnection() {
		return mapByName.containsKey("Connection");
	}

	@Field(offset = 9, length = 0, format = "%s", display = "Connection")
	public String connection() {
		return mapByName.get("Connection").getValue();
	}

	public Map<String, Entry> headerFields() {
		return new HashMap<String, Entry>(mapByName);
	}

	/**
	 * Decode the http header. First we need to convert raw bytes to a char's we
	 * can deal with since Http header is text based. Once converted we can then
	 * accurately determine the Http header length, type of request, etc...
	 */
	@Override
	protected void decodeHeader() {
		/*
		 * Reset previous state
		 */
		this.requestMethod = null;
		this.requestUrl = null;
		this.requestVersion = null;
		this.responseCode = -1;
		this.responseCodeMessage = null;
		mapByName.clear();

		/*
		 * First we need to scan the buffer for an empty new line which identifies
		 * the end of the header that would the 2 sets of '\n' '\r' characters.
		 */
		buf.setLength(0);
		super.getUTF8String(0, buf, HTTP_HEADER_DELIMITER);

		String s = buf.toString();
		String lines[] = s.split("\r\n");
		
//		System.out.println("[" + s + "]");

		for (String line : lines) {
			String c[] = line.split(":", 2);

			if (c.length == 1) {
				c = c[0].split(" ");

				if (c[0].startsWith("HTTP")) {
					this.requestVersion = c[0];
					this.responseCode = Integer.parseInt(c[1]);
					this.responseCodeMessage = c[2];

				} else {

					this.requestMethod = c[0];
					this.requestUrl = c[1];
					this.requestVersion = c[2];
				}
				continue;
			}
			// System.out.printf("[%s]=[%s]\n", c[0], c[1]);
			int offset = s.indexOf(c[0]);
			int length = c[0].length() + c[1].length() + 1;
			Entry entry = new Entry(c[0], c[1].trim(), offset, length);
			mapByName.put(c[0], entry);
		}

		/*
		 * Now resize the buffer to the correct length of the header
		 */
		// setSize(buf.length());
	}

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasHost() {
		return mapByName.containsKey("Host");
	}

	@Field(offset = 4, length = 0, format = "%s", display = "")
	public String host() {
		return mapByName.get("Host").getValue();
	}

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasRequestMethod() {
		return this.requestMethod != null;
	}

	@Field(offset = 0, length = 476 * 8, format = "%s", display = "Request Method")
	public String requestMethod() {
		return this.requestMethod;
	}

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasRequestUrl() {
		return this.requestUrl != null;
	}

	@Field(offset = 1, length = 476 * 8, format = "%s", display = "Request Url")
	public String requestUrl() {
		return this.requestUrl;
	}

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasRequestVersion() {
		return this.requestVersion != null;
	}

	@Field(offset = 2, length = 476 * 8, format = "%s", display = "Request Version")
	public String requestVersion() {
		return this.requestVersion;
	}
	
	@FieldRuntime(field = "responseCode", value = FieldFunction.DESCRIPTION)
	public String hasResponseCodeDesc() {
		return responseCodeMessage();
	}


	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasResponseCode() {
		return this.responseCode != -1;
	}

	@Field(offset = 2, length = 476 * 8, format = "%d", display = "Response Code")
	public int responseCode() {
		return this.responseCode;
	}

	public boolean hasResponseCodeMessage() {
		return this.responseCodeMessage != null;
	}

	public String responseCodeMessage() {
		return this.responseCodeMessage;
	}

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasUserAgent() {
		return mapByName.containsKey("User-Agent");
	}

	@Field(offset = 3, length = 0, format = "%s", display = "User-Agent")
	public String userAgent() {
		return mapByName.get("User-Agent").getValue();
	}
	
	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasContentType() {
		return mapByName.containsKey("Content-Type");
	}


	@Field(offset = 3, length = 0, format = "%s", display = "Content-Type")
	public String contentType() {
		return mapByName.get("Content-Type").getValue();
	}

	@FieldRuntime(FieldFunction.CHECK)
	public boolean hasContentLength() {
		return mapByName.containsKey("Content-Length");
	}
	
	@Field(offset = 3, length = 0, format = "%d", display = "Content-Length")
	public int contentLength() {
		return Integer.parseInt(mapByName.get("Content-Length").getValue());
	}
}
