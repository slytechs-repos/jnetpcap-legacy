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
package org.jnetpcap.packet.format;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;

import junit.framework.TestCase;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.JScanner;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestFormatter
    extends TestCase {

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

	public void _testHtmlCSSFormatter() throws IOException {
		dumpToFormatter(new HtmlCSSFormatter(), "tests/test-vlan.pcap");
	}

	public void _testHtmlTableFormatter() throws IOException {
//		File f = new File("tests/write.html");
//		PrintWriter pw = new PrintWriter(f);
		
		PrintStream pw = System.out;
		pw.format("<html>\n<head><style>\n");
		pw.format("#cl_field_data {color:red;}\n");
		pw.format("</style></head>\n<body>\n\n");
		
		dumpToFormatter(new HtmlTableFormatter(pw), "tests/test-vlan.pcap");
		
		pw.format("</body>\n</html>\n");
		pw.close();
		
		dumpToFormatter(new HtmlTableFormatter(), "tests/test-vlan.pcap");
	}

	public void testTextFormatter() throws IOException {
		dumpToFormatter(new TextFormatter(), "tests/test-vlan.pcap");
	}

	public void _testXmlFormatter() throws IOException {
		dumpToFormatter(new XmlFormatter(), "tests/test-vlan.pcap");
	}

	public void dumpToFormatter(final JFormatter formatter, String file) throws IOException {

		final Pcap pcap = Pcap.openOffline(file, System.err);

		final JPacket packet = new JPacket();
		final JScanner scanner = new JScanner();

		// long start = System.currentTimeMillis();

		pcap.loop(Pcap.LOOP_INFINATE, new PcapHandler<String>() {
			int i = 0;

			public void nextPacket(String user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

				if (i < 157) {
					i++;
					return;
				}

				packet.peer(buffer);

				scanner.scan(packet, JProtocol.ETHERNET_ID);
				try {
					formatter.setFrameIndex(i);
					formatter.format(packet);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				i++;
			}

		}, "");

		// long end = System.currentTimeMillis();
		//
		// System.out.printf("time=%d ms\n", (end - start));

		pcap.close();

	}

}
