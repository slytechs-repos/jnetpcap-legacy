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
package org.jnetpcap.util.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import org.jnetpcap.util.JLogger;
import org.jnetpcap.util.config.JConfig.ClasspathSearch;
import org.jnetpcap.util.config.JConfig.FilesystemSearch;
import org.jnetpcap.util.config.JConfig.SearchPath;
import org.jnetpcap.util.config.JConfig.URLSearch;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class SearchpathString
    extends ConfigString {

	private final static Logger logger = JLogger.getLogger(JConfig.class);

	private final List<String> pathContents = new ArrayList<String>();

	private final Properties properties;

	private final Map<String, String> variables;

	/**
	 * @param template
	 */
	public SearchpathString(String template, Map<String, String> variables,
	    Properties properties) {
		super(template, variables, properties);

		this.variables = variables;
		this.properties = properties;
	}

	private void cleanupString() {
		super.expand("", variables, properties);
		remove("\\\r\n");
		trimToSize();

		start = 0;
		end = -1;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.config.ConfigString#reset()
	 */
	@Override
	public SearchpathString reset() {

		super.reset();
		pathContents.clear();

		return this;
	}

	private boolean splitToComponents() {

		while (scanNext("'", "'", end + 1) && start != -1) {
			if (properties == null) {
				return false;
			}
			String s = substring(start + 1, end).trim();
			if (s.length() == 0) {
				continue;
			}
			pathContents.add(s);
		}

		return (start == -1) ? true : false;

	}

	public SearchPath[] toArray() {
		reset();
		cleanupString();
		splitToComponents();

		List<SearchPath> list = new ArrayList<SearchPath>(pathContents.size());

		for (String s : pathContents) {

			if (s.startsWith("File(")) {
				String content = s.substring("File(".length(), s.length() - 1);
				list.add(new FilesystemSearch(new ConfigString(content, variables,
				    properties)));

			} else if (s.startsWith("Classpath(")) {
				String content = s.substring("Classpath(".length(), s.length() - 1);
				list.add(new ClasspathSearch(new ConfigString(content, variables,
				    properties)));

			} else if (s.startsWith("URL(")) {
				String content = s.substring("URL(".length(), s.length() - 1);
				list
				    .add(new URLSearch(new ConfigString(content, variables, properties)));

			} else {
				logger.warning("unexpected search component type " + s);
			}
		}

		return list.toArray(new SearchPath[list.size()]);
	}

}
