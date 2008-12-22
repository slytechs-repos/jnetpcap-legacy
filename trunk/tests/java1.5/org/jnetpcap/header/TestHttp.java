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

import java.util.Map;

import junit.framework.TestCase;

import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.protocol.tcpip.Html;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Http.Entry;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestHttp
    extends TestCase {

	static {
		try {
			JRegistry.register(Http.class);
			JRegistry.register(Html.class);
		} catch (RegistryHeaderErrors e) {
			e.printStackTrace();
		}
	}

	private Http http = new Http();

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

	public void testRegistration() {
		assertTrue(JRegistry.lookupId(Http.class) > 12);
	}

	public void testOnPacket() {
		PcapPacket packet =
		    TestUtils.getPcapPacket("tests/test-http-jpeg.pcap", 5);
		
		System.out.println(packet.toString());
		
		if (true && packet.hasHeader(http)) {
			Map<String, Entry> map = http.headerFields();
			
			for(Entry e: map.values()) {
				System.out.println(e.toString());
			}
		}
	}

}
