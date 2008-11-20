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
package org.jnetpcap.packet;

import java.io.IOException;
import java.nio.ByteBuffer;

import junit.framework.TestCase;

import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapPacket;
import org.jnetpcap.packet.JBinding.DefaultJBinding;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.packet.header.Ethernet;
import org.jnetpcap.packet.header.Ip4;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestJScanner
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

	public void _testJScannerInit() {
		// May seem simple, but has detected a bug already in initializer :)
		new JScanner();
	}

	public void _testJScannerSizeOf() {
		assertTrue("sizeof=" + JScanner.sizeof(), JScanner.sizeof() > 0
		    && JScanner.sizeof() < 100000);
	}

	public void _testScanOnePacket() throws IOException {
		JPacket packet = new PcapPacket(64);
		packet.setByteArray(0, new byte[] {
		    (byte) 0xa0,
		    (byte) 0xa1,
		    (byte) 0xa2,
		    (byte) 0xa3,
		    (byte) 0xa4,
		    (byte) 0xa5,

		    (byte) 0xb0,
		    (byte) 0xb1,
		    (byte) 0xb2,
		    (byte) 0xb3,
		    (byte) 0xb4,
		    (byte) 0xb5,

		    (byte) 0x00,
		    (byte) 0x08, });

		JScanner scanner = new JScanner();
		scanner.scan(packet, Ethernet.ID);

		TextFormatter out = new TextFormatter();
		out.format(packet);
	}

	public void testInstallJBinding() throws IOException {
		JPacket packet = new PcapPacket(64);
		packet.setByteArray(0, VariousInMemoryPackets.PACKET_1);

		JBinding bindEthernet =
		    new DefaultJBinding(Ip4.ID, Ethernet.ID, Ethernet.ID) {
			    private Ethernet eth =
			        JHeaderPool.getDefault().getHeader(JProtocol.ETHERNET);

			    public int scanForNextHeader(JPacket packet, int offset) {
				    return (eth.type() == 0x800) ? Ethernet.ID : JBinding.NULL_ID;
			    }

		    };

		JRegistry.addBinding(Ethernet.ID, bindEthernet);

		JScanner scanner = new JScanner();
		scanner.reloadAll();

		scanner.scan(packet, Ethernet.ID);

		TextFormatter out = new TextFormatter();
		out.format(packet);
	}

	public void testScanFile() throws IOException {
		StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline("tests/test-l2tp.pcap", errbuf);

		final JPacket packet = new PcapPacket();
		final JScanner scanner = new JScanner();

		long start = System.currentTimeMillis();
		final TextFormatter out = new TextFormatter();

		pcap.loop(Pcap.LOOP_INFINATE, new ByteBufferHandler<String>() {
			int i = 0;

			public void nextPacket(String user, PcapHeader header, ByteBuffer buffer) {

				if (i == 200) {
					pcap.breakloop();
					return;
				}

				System.out.println("\nPacket #" + i);

				packet.peer(buffer);

				scanner.scan(packet, JProtocol.ETHERNET_ID);
				// try {
				out.setFrameIndex(i++);
				// out.format(packet);
				System.out.println(packet.toString());
				// } catch (IOException e) {
				// // TODO Auto-generated catch block
				// e.printStackTrace();
				// }
			}

		}, "");

		long end = System.currentTimeMillis();

		System.out.printf("time=%d ms\n", (end - start));

		pcap.close();
	}

}
