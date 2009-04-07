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
package org.jnetpcap.newstuff;

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

	protected final StringBuilder buf = new StringBuilder(1024);

	private MessageType messageType;

	/**
	 * Decode the http header. First we need to convert raw bytes to a char's we
	 * can deal with since Http header is text based. Once converted we can then
	 * accurately determine the Http header length, type of request, etc...
	 */
	@Override
	protected void decodeHeader() {
		
		super.clearFields();

		/*
		 * First we need to scan the buffer for an empty new line which identifies
		 * the end of the header that would the 2 sets of '\n' '\r' characters.
		 */
		buf.setLength(0);
		super.getUTF8String(0, buf, HEADER_DELIMITER);

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

			super.addField(name, value, offset, length);
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
