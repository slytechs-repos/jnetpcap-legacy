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
package org.jnetpcap.protocol.application;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.util.JThreadLocal;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(nicname = "Html", suite = ProtocolSuite.APPLICATION)
public class Html
    extends
    JHeader {

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		return buffer.size() - offset;
	}

	@Bind(to = Http.class, stringValue = "text/html")
	public static boolean bind2Http(JPacket packet, Http http) {
		return http.hasContentType() && http.contentType().startsWith("text/html;");
	}

	private final JThreadLocal<StringBuilder> stringLocal =
	    new JThreadLocal<StringBuilder>(StringBuilder.class);

	private String page;

	@Dynamic(Field.Property.LENGTH)
	public int pageLength() {
		return size() * 8;
	}

	@Field(offset = 0, format = "#textdump#")
	public String page() {
		return this.page;
	}

	@Override
	protected void decodeHeader() {
		final StringBuilder buf = stringLocal.get();
		buf.setLength(0);

		super.getUTF8String(0, buf, size());

		this.page = buf.toString();
	}
}
