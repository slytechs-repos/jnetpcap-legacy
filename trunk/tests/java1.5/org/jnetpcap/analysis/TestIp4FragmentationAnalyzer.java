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
package org.jnetpcap.analysis;

import java.io.IOException;

import junit.framework.TestCase;

import org.jnetpcap.analysis.tcpip.AbstractFragmentationAnalyzer;
import org.jnetpcap.analysis.tcpip.Ip4FragmentationAnalyzer;
import org.jnetpcap.analysis.tcpip.Ip4Reassembler;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.packet.header.Ip4;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class TestIp4FragmentationAnalyzer
    extends TestCase {

	private static final String AFS = "tests/test-afs.pcap";

	private static final String HTTP = "tests/test-http-jpeg.pcap";

	private JController controller;

	private AbstractFragmentationAnalyzer ip4Analyzer;

	private Ip4Reassembler ip4Defrag;

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		controller = new JController();
		ip4Analyzer = new Ip4FragmentationAnalyzer();
		controller.addAnalyzer(ip4Analyzer, Ip4.ID);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	public void testFragAnalyze2Packets() throws IOException {

		TextFormatter out = new TextFormatter(System.out);

		PcapPacket packet1 = TestUtils.getPcapPacket(AFS, 125);
		PcapPacket packet2 = TestUtils.getPcapPacket(AFS, 126);

		controller.nextPacket(packet1, null);
		controller.nextPacket(packet2, null);

		AbstractAnalysis<FragmentSequence, FragmentSequenceEvent> seq =
		    new FragmentSequence();
		Ip4 ip = new Ip4();
		packet2.getHeader(ip);

		assertNotNull(ip.getAnalysis(seq));

		// out.format(ip);

	}

	public void testFragAnalyzeBunchOfPackets() throws IOException {

		TextFormatter out = new TextFormatter(System.out);
		AbstractAnalysis<FragmentSequence, FragmentSequenceEvent> seq =
		    new FragmentSequence();
		Ip4 ip = new Ip4();

		for (JPacket packet : TestUtils.getJPacketIterable(AFS, 0, 128)) {
			controller.nextPacket(packet, null);

			packet.getHeader(ip);

			// out.format(ip);
		}
	}

	public void testIp4Reasemble() throws IOException {

		ip4Defrag = new Ip4Reassembler(ip4Analyzer);

		controller.add(new JPacketHandler<Object>() {
			Ip4 ip = new Ip4();
			TextFormatter out = new TextFormatter(System.out);
			FragmentReassembly reassembly = new FragmentReassembly();

			public void nextPacket(JPacket packet, Object user) {
				try {
					if (packet.hasHeader(ip) && ip.isReassembled()) {
						out.printf("\nFrame #%d", packet.getFrameNumber());
						out.format(ip);
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

		}, null);

		for (JPacket packet : TestUtils.getJPacketIterable(AFS, 124, 128)) {
			controller.nextPacket(packet, null);
		}
	}

}
