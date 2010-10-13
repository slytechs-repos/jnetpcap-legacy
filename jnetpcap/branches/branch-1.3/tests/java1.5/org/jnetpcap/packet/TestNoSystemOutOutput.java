/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintStream;

import org.jnetpcap.packet.format.TextFormatter;

import junit.framework.TestCase;

/**
 * Perform various tasks that should not generate output to either System.out or
 * System.err. Redirect those to a StringBuilder (Appendable) and check for 0
 * output in the buffer. This ensure that nothing (debug messages especially)
 * has been generated inadvertantly.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestNoSystemOutOutput
    extends
    TestCase {

	private final static File DIR = new File("tests");

	private PrintStream savedOut;

	private PrintStream savedErr;

	private ByteArrayOutputStream out;

	private TextFormatter DISGARD_OUTPUT = new TextFormatter(TestUtils.DEV_NULL);

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		savedOut = System.out;
		savedErr = System.err;

		out = new ByteArrayOutputStream();
		System.setOut(new PrintStream(out));
		System.setErr(new PrintStream(out));
	}

	private void reset() {
		out = new ByteArrayOutputStream();
		System.setOut(new PrintStream(out));
		System.setErr(new PrintStream(out));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		System.setOut(savedOut);
		System.setErr(savedErr);
	}

	public void testSystemOutRedirectionIsWorking() {
		assertTrue("redirection failed", out.size() == 0);

		System.err.println("hello");
		assertFalse("redirection failed", out.size() == 0);
		reset();
	}

	public void testNoOutputFromCoreProtocols() throws IOException {

		String[] files = DIR.list(new FilenameFilter() {

			public boolean accept(File dir, String name) {
				return name.endsWith(".pcap");
			}

		});

//		int count = 0;
		for (String f : files) {
			for (PcapPacket packet : TestUtils.getIterable(DIR + "/" + f)) {
//				savedOut.printf("TestNoSystemOutput() #%d\n", count ++);
//				savedOut.flush();
//				
				
				DISGARD_OUTPUT.format(packet);
				assertTrue("unexpected System.out output found " + f + ": packet="
				    + packet.toString() + "\noutput found=" + out.toString(), out.size() == 0);
			}
		}
	}

}
