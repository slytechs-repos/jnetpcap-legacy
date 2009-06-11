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
package org.jnetpcap.protocol.voip;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.analysis.JController;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestVoip
    extends
    TestUtils {

	private static final String SIP = "tests/test-sip-rtp.pcap";
	private static final String SIP_G711 = "tests/test-sip-rtp-g711.pcap";

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

	public void testSip() {
		Sip sip = new Sip();
		Sdp sdp = new Sdp();
		PcapPacket packet = super.getPcapPacket(SIP, 223 - 1);
		if (packet.hasHeader(sip)) {
			System.out.printf("%s", sip);

			if (packet.hasHeader(sdp)) {
				System.out.printf("%s", sdp);

			}
		} else {
			System.out.printf(packet.toString());
		}
	}

	public void testSipAnalyzer() {
		Sip sip = new Sip();

		SipAnalyzer a = new SipAnalyzer();
		JRegistry.addAnalyzer(a);
		JRegistry.getAnalyzer(JController.class).addAnalyzer(a,
		    JRegistry.lookupId(Sip.class));

		a.add(new SipHandler() {

			public void processSip(Sip sip) {
				if (sip.contentLength() > 0) {
					System.out.printf("\n#%d%s", sip.getPacket().getFrameNumber(), sip);
				}
			}

		});

		Pcap pcap = super.openOffline(SIP_G711);
		
		pcap.analyze();
	}

}
