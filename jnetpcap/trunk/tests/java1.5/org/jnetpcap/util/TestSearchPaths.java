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

import java.io.IOException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

import junit.framework.TestCase;

import org.jnetpcap.util.config.JConfig;
import org.jnetpcap.util.config.JConfig.SearchPath;
import org.jnetpcap.util.resolver.Resolver;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestSearchPaths
    extends TestCase {

	private static Logger logger = JLogger.getLogger(JConfig.class);

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	public void _testCacheSearchPath() throws IOException {
		logger.setLevel(Level.FINER);

		assertNotNull("failed to locate IP resolver file", JConfig.getInputStream(
		    "IP", Resolver.RESOLVER_SEARCH_PATH_PROPERTY));

	}

	public void _testResourceSearchPathOuiTxtFile() throws IOException {
		logger.setLevel(Level.FINER);

		assertNotNull("failed to locate oui.txt resource file", JConfig
		    .getResourceInputStream("oui.txt"));
	}

	public void _testResourceSearchPathOuiTxtURL() throws IOException {
		logger.setLevel(Level.FINER);

		URL url = null;
		assertNotNull("failed to locate oui.txt resource file", url =
		    JConfig.getResourceURL("oui.txt"));

		System.out.println(url);

	}

	public void testSearchPathFromProperty() throws IOException {
		logger.setLevel(Level.FINER);

		for (SearchPath p : JConfig
		    .createSearchPath(Resolver.RESOLVER_SEARCH_PATH_PROPERTY)) {

			System.out.println(p.toString());
		}
	}

}
