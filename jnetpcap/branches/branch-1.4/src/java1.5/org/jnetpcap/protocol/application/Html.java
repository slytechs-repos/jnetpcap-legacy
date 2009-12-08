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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
 * Hyper Text Markup Language header definition.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(nicname = "Html", suite = ProtocolSuite.APPLICATION)
public class Html
    extends
    JHeader {

	/**
	 * Html tag instance parsed from the html document
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class HtmlTag {

		public enum Type {
			ATOMIC,
			CLOSE,
			OPEN,
		}

		private final int end;

		private Map<Tag.Param, String> params = Collections.emptyMap();

		private final String source;

		private final int start;

		private Tag tag;

		private final String tagString;

		final Type type;

		/**
		 * @param type
		 * @param url
		 */
		public HtmlTag(
		    Tag tag,
		    Type type,
		    String tagString,
		    String source,
		    int start,
		    int end) {

			this.tag = tag;
			this.type = type;
			this.tagString = tagString;
			this.source = source;
			this.start = start;
			this.end = end;

			if (type != Type.ATOMIC) {
				parseTag(tag, tagString);
			}

		}

		public final int getEnd() {
			return this.end;
		}

		public final Map<Tag.Param, String> getParams() {
			return this.params;
		}

		public final String getSource() {
			return this.source;
		}

		public final int getStart() {
			return this.start;
		}

		public final Tag getTag() {
			return this.tag;
		}

		/**
		 * @return
		 */
		public String getTagString() {
			return this.tagString;
		}

		public final Type getType() {
			return this.type;
		}

		/**
		 * @param tag
		 * @param tagString
		 */
		private void parseTag(Tag tag, String tagString) {
			String[] p = tagString.split(" ");

			if (p.length > 1) {
				this.params = new HashMap<Tag.Param, String>(p.length - 1);
			}

			for (String s : p) {
				s = s.trim();
				String[] c = s.split("=");

				if (c.length == 2) {
					if (c[1].charAt(0) == '"' || c[1].charAt(0) == '\"') {
						c[1] = c[1].substring(1, c[1].length() - 2);
					}
					this.params.put(Tag.Param.parseStringPrefix(c[0]), c[1]);
				}
			}
		}

		public String toString() {
			StringBuilder b = new StringBuilder();

			switch (type) {
				case ATOMIC:
					// b.append(tag.name()).append("<>");
					break;
				case CLOSE:
					b.append(tag.name()).append("/>");
					break;
				case OPEN:
					b.append(tag.name()).append('<');
					break;
			}

			if (tag == Tag.TEXT) {
				// b.append(tag.toString()).append('=');
				b.append('"');
				b.append(parserLocal.get().format(tagString));
				b.append('"');

			} else if (params.isEmpty() == false) {
				b.append('=');
				b.append(params.toString());

			}

			return b.toString();
		}

	}

	/**
	 * Table of supported HTML tags.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Tag {
		A,
		B,
		BODY,
		BUTTON,
		CAPTION,
		CENTER,
		DIV,
		EM,
		FORM,
		H1,
		H2,
		H3,
		H4,
		H5,
		H6,
		HEAD,
		HTML,
		I,
		IFRAME,
		IMG,
		INPUT,
		LABEL,
		LI,
		LINK("rel", "type", "href"),
		META,
		NOSCRIPT,
		OBJECT,
		OL,
		P,
		REL,
		SCRIPT,
		SPAN,
		TABLE,
		TBODY,
		TD,
		TEXT,
		TH,
		TITLE,
		TR,
		U,
		UL,
		UNKNOWN;

		/**
		 * Table of tag parameters
		 * 
		 * @author Mark Bednarczyk
		 * @author Sly Technologies, Inc.
		 */
		public enum Param {
			ALT,
			CLASS,
			HEIGHT,
			HREF,
			ID,
			SRC,
			TITLE,
			TYPE,
			UNKNOWN,
			WIDTH;

			public static Param parseStringPrefix(String name) {
				for (Param p : values()) {
					if (name.toUpperCase().startsWith(p.name())) {
						return p;
					}
				}

				return UNKNOWN;
			}

		}

		public static Tag parseStringPrefix(String name) {
			for (Tag t : values()) {
				if (name.toUpperCase().startsWith(t.name())) {
					return t;
				}
			}

			return UNKNOWN;
		}

		private final String[] params;

		private Tag(String... params) {

			int i = 0;
			for (String p : params) {
				params[i++] = p.trim().toUpperCase();
			}
			this.params = params;

		}

		public final String[] getParams() {
			return this.params;
		}

	}

	@Bind(to = Http.class, stringValue = "text/html")
	public static boolean bind2Http(JPacket packet, Http http) {
		return http.hasContentType() && http.contentType().startsWith("text/html;");
	}

	@Bind(to = Http.class, stringValue = "text/css")
	public static boolean bind2HttpAsCSS(JPacket packet, Http http) {
		return http.hasContentType() && http.contentType().startsWith("text/css;");
	}

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		return buffer.size() - offset;
	}

	private String page;

	private static final JThreadLocal<StringBuilder> stringLocal =
	    new JThreadLocal<StringBuilder>(StringBuilder.class);

	private static final JThreadLocal<HtmlParser> parserLocal =
	    new JThreadLocal<HtmlParser>(HtmlParser.class);

	private HtmlTag[] tags;

	private HtmlTag[] links;

	@Override
	protected void decodeHeader() {
		final StringBuilder buf = stringLocal.get();
		buf.setLength(0);

		super.getUTF8String(0, buf, size());

		this.page = buf.toString();

		this.tags = null;
		this.links = null;
	}

	@Field(offset = 0, format = "#textdump#")
	public String page() {
		return this.page;
	}

	@Dynamic(Field.Property.LENGTH)
	public int pageLength() {
		return size() * 8;
	}

	public HtmlTag[] tags() {
		if (tags == null) {
			tags = parserLocal.get().decodeAllTags(this.page);
		}

		return tags;
	}

	public HtmlTag[] links() {
		if (this.links == null) {
			this.links = parserLocal.get().decodeLinks(tags());
		}

		return this.links;
	}

	public String toString() {
		StringBuilder b = new StringBuilder();

		for (HtmlTag t : tags()) {
			b.append(t.toString()).append("\n");
		}

		return b.toString();
	}
}
