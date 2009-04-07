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
package org.jnetpcap.packet;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.util.JThreadLocal;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AbstractMessageHeader
    extends JMappedHeader {

	public enum MessageType {
		RESPONSE,
		REQUEST
	}

	private final static char[] HEADER_DELIMITER = {
	    '\r',
	    '\n',
	    '\r',
	    '\n' };

	private final JThreadLocal<StringBuilder> stringLocal =
	    new JThreadLocal<StringBuilder>(StringBuilder.class);

	private MessageType messageType;

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {

		/*
		 * Since we could be reading from a TCP segment that does not contain a
		 * message header, we check the first character if atleast its a valid
		 * character for any of the possible values. The first line defines a
		 * consise set of chars.
		 */
		if (checkValidFirstChars(buffer, offset) == false) {
			return 0;
		}

		/*
		 * We need to scan the buffer for an empty new line which identifies the end
		 * of the header that would the 2 sets of '\n' '\r' characters.
		 */
		int len = buffer.findUTF8String(offset, HEADER_DELIMITER);

		return len;
	}

	private final static String[] VALID_CHARS = {
	    "GET",
	    "PUT",
	    "POS",
	    "CON",
	    "CAN", // CONNECT, CANCEL
	    "HEA",
	    "HTT", // HEAD, HTTP
	    "OPT", // OPTIONS
	    "DEL", // DELETE
	    "TRA", // TRACE
	    "SIP", // SIP
	    "INV", // INVITE
	};

	private static boolean checkValidFirstChars(JBuffer buffer, int offset) {
		final String first = buffer.getUTF8String(offset, 3);
		for (String c : VALID_CHARS) {
			if (first.equals(c)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Decode the http header. First we need to convert raw bytes to a char's we
	 * can deal with since Http header is text based. Once converted we can then
	 * accurately determine the Http header length, type of request, etc...
	 */
	@Override
	protected void decodeHeader() {

		super.clearFields();

		/*
		 * We already know the length of the header, so just get the raw chars
		 */
		final StringBuilder buf = stringLocal.get();
		buf.setLength(0);
		int len = super.getLength();
		super.getUTF8String(0, buf, len);

		String s = buf.toString();
		String lines[] = s.split("\r\n");

		// System.out.println("[" + s + "]");

		for (String line : lines) {
			String c[] = line.split(":", 2);

			if (c.length == 1) {
				decodeFirstLine(c[0]);
				continue;
			}

			// System.out.printf("[%s]=[%s]\n", c[0], c[1]);
			String name = c[0];
			String value = c[1];
			int offset = s.indexOf(name + ":");
			int length = name.length() + value.length() + 1;

			super.addField(name.trim(), value.trim(), offset, length);
		}
	}

	protected abstract void decodeFirstLine(String line);

	/**
	 * @param type
	 */
	public void setMessageType(MessageType type) {
		this.messageType = type;
	}

	public MessageType getMessageType() {
		return this.messageType;
	}

}
