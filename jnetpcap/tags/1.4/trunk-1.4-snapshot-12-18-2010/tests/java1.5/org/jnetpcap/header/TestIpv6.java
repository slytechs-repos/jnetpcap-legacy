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
package org.jnetpcap.header;

import java.io.IOException;

import junit.framework.TestCase;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.protocol.lan.Ethernet;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestIpv6
    extends TestCase {
	
	private final static Appendable OUT = TestUtils.DEV_NULL;
//	private final static Appendable OUT = System.out;

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

	/**
	 * Printing to DEV_NULL still causes entire packet structure to be decoded and
	 * dumped to /dev/null while using every available header found in the packet.
	 * Good stress test for Ip6 based packets.
	 * 
	 * @throws IOException
	 */
	public void testScanIpv6File() throws IOException {
		TextFormatter out = new TextFormatter(OUT);
		out.setResolveAddresses(false);

		int i = 0;
		Ethernet eth = new Ethernet();
		for (PcapPacket packet : TestUtils.getIterable("tests/test-ipv6.pcap")) {

			System.out.println(packet.toDebugString());
			if (packet.hasHeader(eth)) {
				out.format(eth);
			}

			out.setFrameIndex(i++);
			out.format(packet);
		}
	}

}
