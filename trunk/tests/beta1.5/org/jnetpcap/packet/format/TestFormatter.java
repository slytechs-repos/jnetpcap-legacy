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
import java.nio.ByteBuffer;

import junit.framework.TestCase;

import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;

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

	public void testTextFormatter() throws IOException {
		dumpToFormatter(new TextFormatter(), "tests/test-vlan.pcap");
	}

	public void _testXmlFormatter() throws IOException {
		dumpToFormatter(new XmlFormatter(), "tests/test-vlan.pcap");
	}

	public void dumpToFormatter(final JFormatter formatter, String file)
	    throws IOException {

		StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline(file, errbuf);

		final JPacket packet = new PcapPacket(Type.POINTER);
		final JScanner scanner = new JScanner();

		// long start = System.currentTimeMillis();

		pcap.loop(Pcap.LOOP_INFINATE, new ByteBufferHandler<String>() {
			int i = 0;

			public void nextPacket(PcapHeader header, ByteBuffer buffer, String user) {

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
