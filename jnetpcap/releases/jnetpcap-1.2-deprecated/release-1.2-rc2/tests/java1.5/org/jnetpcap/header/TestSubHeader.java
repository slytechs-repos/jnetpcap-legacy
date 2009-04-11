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

import junit.framework.TestCase;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.header.Ip4;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestSubHeader
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

	public void _testSyntaxText() {
		Ip4 ip = new Ip4();
		Ip4.Timestamp ts = new Ip4.Timestamp();
		Ip4.LooseSourceRoute lsroute = new Ip4.LooseSourceRoute();
		Ip4.StrictSourceRoute ssroute = new Ip4.StrictSourceRoute();

		JPacket packet = null;

		if (packet.hasHeader(ip) && ip.hasSubHeaders()) {

			if (ip.hasSubHeader(lsroute)) {

			}

			if (ip.hasSubHeader(ssroute)) {

			}

			if (ip.hasSubHeader(ts)) {

			}
		}
	}

	public void test1() {
		JPacket packet =
		    TestUtils.getPcapPacket("tests/test-icmp-recordroute-opt.pcap", 0);
		assertNotNull(packet);

		System.out.println(packet.toString());

		System.out.println(packet.getState().toHexdump());
		System.out.println(packet.getState().toDebugString());
	}

}
