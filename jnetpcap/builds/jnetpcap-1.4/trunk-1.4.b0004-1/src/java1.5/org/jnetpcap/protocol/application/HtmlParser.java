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
package org.jnetpcap.protocol.application;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.protocol.application.Html.HtmlTag;
import org.jnetpcap.protocol.application.Html.Tag;
import org.jnetpcap.util.JThreadLocal;

/**
 * Html header parser.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class HtmlParser {

	private int e = 0;

	private int s = 0;

	private String str = null;

	@SuppressWarnings("unchecked")
	private static final JThreadLocal<ArrayList> listLocal =
	    new JThreadLocal<ArrayList>(ArrayList.class);

	@SuppressWarnings("unchecked")
	public HtmlTag[] decodeAllTags(String page) {
		this.e = 0;
		this.s = e;

		final List<HtmlTag> list = listLocal.get();
		list.clear();

		int textStart = 0;
		while (true) {
			final HtmlTag tag = nextTag(page, '<', '>');
			if (tag == null) {
				break;
			}

			if (textStart != this.s) {
				String text = page.substring(textStart, this.s);
				if (text.length() != 0) {
					list.add(new HtmlTag(Tag.TEXT, HtmlTag.Type.ATOMIC, text, page,
					    textStart, this.s));
				}
			}

			textStart = this.e + 1;

			list.add(tag);
		}

		return list.toArray(new HtmlTag[list.size()]);
	}

	@SuppressWarnings("unchecked")
	public HtmlTag[] decodeLinks(HtmlTag[] tags) {
		List<HtmlTag> links = listLocal.get();
		links.clear();

		for (HtmlTag t : tags) {
			switch (t.getTag()) {
				case A:
				case LINK:
				case IMG:
				case SCRIPT:
				case FORM:
					if (t.type == HtmlTag.Type.OPEN) {
						links.add(t);
					}
			}
		}

		return links.toArray(new HtmlTag[links.size()]);
	}

	private String extractBounded(String str, char start, char end) {
		if (this.str != str) {
			this.s = 0;
			this.e = 0;
			this.str = str;
		}

		s = str.indexOf('<', e);
		e = str.indexOf('>', s);

		return (s == -1 || e == -1) ? null : str.substring(s + 1, e).trim()
		    .replace("\r\n", "");
	}

	private HtmlTag nextTag(String str, char start, char end) {

		String tagString = extractBounded(str, start, end);
		if (tagString == null) {
			return null;
		}

		Tag tag;
		HtmlTag.Type type = HtmlTag.Type.OPEN;
		if (tagString.charAt(0) == '/') {
			tagString = tagString.substring(1);
			type = HtmlTag.Type.CLOSE;
		}

		tag = Tag.parseStringPrefix(tagString);

		if (tag == null) {
			return null;
		}

		HtmlTag ht = new HtmlTag(tag, type, tagString, this.str, this.s, this.e);

		return ht;
	}

	/**
	 * @param tagString
	 * @return
	 */
	public String format(String str) {

		str = str.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
		return str;
	}

}
