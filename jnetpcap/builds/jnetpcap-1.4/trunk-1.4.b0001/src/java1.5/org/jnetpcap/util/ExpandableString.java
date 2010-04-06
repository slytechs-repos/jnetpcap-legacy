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
package org.jnetpcap.util;

import java.util.LinkedList;
import java.util.List;

/**
 * A special string that allows easy expandibility within it. The
 * ExpandableString is made up of 2 parts. A template string and a work buffer.
 * Whenever a reset() call is made, the buffer is replaced with the contents of
 * the template. The various replace calls, change the buffer by replacing
 * certain parts, recursively. Subclasses perform specific expand operations,
 * that are suited for their needs. Substitutions between single quotes are
 * omitted and returned untouched. Everything else that is not single quoted,
 * can be expanded. Escape character, the back-slash, is treated with a lot of
 * respect.
 * <p>
 * For example ConfigString subclass replaces variables and properties (marked
 * with $ and &#64; signs respectively) with contents from various maps and
 * properties.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class ExpandableString
    extends JStringBuilder {

	protected int count = 0;

	protected int end;

	private final List<String> quoted = new LinkedList<String>();

	protected int start;

	private String template;

	public ExpandableString(String template) {
		this.template = template;
		super.append(template);
	}

	/**
	 * @return the template
	 */
	public final String getTemplate() {
		return this.template;
	}

	public boolean remove(String seq) {
		return replaceSequence(seq, "", "");
	}

	public boolean replaceSequence(String open, String close, String with) {
		while (scanNext(open, close) && start != -1) {
			super.replace(start, end + 1, with);
		}

		return (start == -1) ? true : false;
	}

	public ExpandableString reset() {
		super.setLength(0);
		super.append(template);
		this.start = 0;
		this.end = 0;

		return this;
	}

	protected boolean restoreQuotes() {
		while (scanNext("\\\\'", "\\\\'") && start != -1) {
			super.replace(start, end + 3, quoted.remove(0));
		}

		return (start == -1) ? true : false;
	}

	protected boolean saveQuotes() {
		quoted.clear();

		while (scanNext("'", "'") && start != -1) {

			quoted.add(super.substring(start, end + 1));

			super.replace(start, end + 1, "\\\\'\\\\'"); // Twice escaped empty quote
		}

		return (start == -1) ? true : false;
	}

	protected boolean scanNext(String open, String close) {
		return scanNext(open, close, 0);
	}

	protected boolean scanNext(String open, String close, int offset) {

		start = super.indexOf(open, offset);
		if (start == -1) {
			return true; // NORMAL EXIT HERE - We're done
		}

		/*
		 * Check for escaped characters
		 */
		if (start != 0 && super.charAt(start - 1) == '\\') {
			return scanNext(open, close, start + 1); // Resume scan just passed it
		}

		if (scanNextEnd(close, start + 1) == false) {
			return false;
		}

		count++;

		return true;
	}

	private boolean scanNextEnd(String close, int offset) {
		end = super.indexOf(close, offset);
		if (end == -1) {
			return false; // Missing matching close
		}

		if (end != 0 && super.charAt(end - 1) == '\\') {
			return scanNextEnd(close, end + 1);
		}

		return true;
	}

	/**
	 * @param template
	 *          the template to set
	 */
	public final void setTemplate(String template) {
		this.template = template;
		reset();
	}

	/**
	 * @return
	 */
	public String template() {
		return this.template;
	}

	public String toString() {
		return super.toString();
	}
}
