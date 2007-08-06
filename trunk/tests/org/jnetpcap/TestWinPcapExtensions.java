/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap;

import java.nio.ByteBuffer;
import java.util.Date;

import junit.framework.TestCase;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jnetpcap.winpcap.WinPcap;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestWinPcapExtensions
    extends TestCase {

	private static final Log logger = LogFactory.getLog(TestPcapJNI.class);

	private final static String device = "\\Device\\NPF_{BC81C4FC-242F-4F1C-9DAD-EA9523CC992D}";

	private final static String fname = "tests/test-l2tp.pcap";

	private StringBuilder errbuf;

	/**
	 * @throws java.lang.Exception
	 */
	protected void setUp() throws Exception {

		errbuf = new StringBuilder();
	}

	/**
	 * @throws java.lang.Exception
	 */
	protected void tearDown() throws Exception {
	}

	public void testIsWinPcapExtSupported() {
		String os = System.getProperty("os.name");

		/*
		 * WinPcap is only available on windows based systems.
		 */
		if (os.startsWith("Windows")) {
			assertTrue(WinPcap.isSupported());
		} else {
			assertFalse(WinPcap.isSupported());
		}
	}

	/**
	 * Test disabled, as it requires live packets to capture. To enable the test
	 * just rename the method, by removing the prefix SKIP. Then make sure there
	 * are live packets to be captured.
	 */
	public void testOpenLiveAndDispatch() {

		WinPcap winPcap = WinPcap.openLive(device, 10000, 1, 60 * 1000, errbuf);
		assertNotNull(winPcap);

		PcapHandler handler = new PcapHandler() {

			public void nextPacket(Object user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

				System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
				    .toString(), new Date(seconds * 1000).toString(), caplen, len,
				    buffer.capacity());
			}
		};

		winPcap.dispatch(10, handler, "Hello");

		winPcap.close();
	}

}
