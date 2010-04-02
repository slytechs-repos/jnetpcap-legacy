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
package org.jnetpcap.newstuff.analysis.flow;

import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.JFormatter;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestFlowKey
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

	private final static String HTTP = "tests/test-http-jpeg.pcap";

	public void testFlowKey() {
		PcapPacket packet3 = TestUtils.getPcapPacket(HTTP, 3);
		PcapPacket packet5 = TestUtils.getPcapPacket(HTTP, 5);
		PcapPacket packet19 = TestUtils.getPcapPacket(HTTP, 19);

		JFlowKey key3 = packet3.getState().getFlowKey();
		JFlowKey key5 = packet5.getState().getFlowKey();
		JFlowKey key19 = packet19.getState().getFlowKey();

		// System.out.printf("fk3=%s fk5=%s fk19=%s\n", key3.toDebugString(), key5
		// .toDebugString(), key19.toDebugString());

		assertEquals(key3.hashCode(), key5.hashCode());
		assertTrue(key3.equals(key5));
		assertFalse(key3.toDebugString(), key3.equals(key19));

		// System.out.println(packet3.toString());
		// System.out.println(packet5.toString());
	}

	public void testFlowMap() {
		JFormatter.setDefaultResolveAddress(true);
		
		StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline("tests/test-http-jpeg.pcap", errbuf);
		if (pcap == null) {
			fail(errbuf.toString());
		}

		try {
			JFlowMap map = new JFlowMap();

			pcap.loop(Pcap.LOOP_INFINATE, map, null);

			System.out.println(map.toString());
			
			for (JFlow flow: map.values()) {
				if (flow.size() == 18) {
					List<JPacket> list = flow.getAll();
					System.out.println(list.get(0));
				}
			}

		} finally {
			pcap.close();
		}
	}

}
