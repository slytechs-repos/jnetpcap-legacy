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

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapUtils;
import org.jnetpcap.packet.JBinding.DefaultJBinding;
import org.jnetpcap.packet.header.Ethernet;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.packet.header.Ip6;
import org.jnetpcap.packet.header.L2TP;
import org.jnetpcap.packet.header.PPP;
import org.jnetpcap.packet.header.Payload;
import org.jnetpcap.packet.header.Tcp;
import org.jnetpcap.packet.header.Udp;

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

	public void testJScannerInit() {
		// May seem simple, but has detected a bug already in initializer :)
		new JScanner();
	}

	public void testJScannerSizeOf() {
		assertTrue("sizeof=" + JScanner.sizeof(), JScanner.sizeof() > 0
		    && JScanner.sizeof() < 100000);
	}

	public void testLocalBindings() {
		JScanner scanner = new JScanner();
		scanner.loadBindings(Ethernet.ID, new JBinding[] {
		    new DefaultJBinding(Ip4.ID, Ethernet.ID) {

			    public int checkLength(JPacket packet, int offset) {
				    // TODO Auto-generated method stub
				    throw new UnsupportedOperationException("Not implemented yet");
			    }

		    },
		    new DefaultJBinding(Ip4.ID, Ethernet.ID) {

			    public int checkLength(JPacket packet, int offset) {
				    // TODO Auto-generated method stub
				    throw new UnsupportedOperationException("Not implemented yet");
			    }

		    },
		    new DefaultJBinding(Ip4.ID, Ethernet.ID) {

			    public int checkLength(JPacket packet, int offset) {
				    // TODO Auto-generated method stub
				    throw new UnsupportedOperationException("Not implemented yet");
			    }

		    },
		    new DefaultJBinding(Ip4.ID, Ethernet.ID) {

			    public int checkLength(JPacket packet, int offset) {
				    // TODO Auto-generated method stub
				    throw new UnsupportedOperationException("Not implemented yet");
			    }

		    },

		});

		scanner.loadBindings(Ethernet.ID, new JBinding[] {
		    new DefaultJBinding(Ip6.ID, Ethernet.ID) {

			    public int checkLength(JPacket packet, int offset) {
				    // TODO Auto-generated method stub
				    throw new UnsupportedOperationException("Not implemented yet");
			    }

		    },
		    new DefaultJBinding(Ip4.ID, Ethernet.ID) {

			    public int checkLength(JPacket packet, int offset) {
				    // TODO Auto-generated method stub
				    throw new UnsupportedOperationException("Not implemented yet");
			    }

		    },
		    new DefaultJBinding(Ip4.ID, Ethernet.ID) {

			    public int checkLength(JPacket packet, int offset) {
				    // TODO Auto-generated method stub
				    throw new UnsupportedOperationException("Not implemented yet");
			    }

		    },
		    new DefaultJBinding(Ip4.ID, Ethernet.ID) {

			    public int checkLength(JPacket packet, int offset) {
				    // TODO Auto-generated method stub
				    throw new UnsupportedOperationException("Not implemented yet");
			    }

		    },

		});

	}

	public void testScanOnePacket() {
		JPacket packet = new JPacket(64);
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

		dumpPacket(packet);
	}

	public void testScanFile() throws IOException {
		final Pcap pcap = Pcap.openOffline("tests/test-l2tp.pcap", System.err);

		final JPacket packet = new JPacket();
		final JScanner scanner = new JScanner();

		long start = System.currentTimeMillis();

		pcap.loop(Pcap.LOOP_INFINATE, new PcapHandler<String>() {
			int i = 0;

			public void nextPacket(String user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {
				
				if (i == 200) {
					pcap.breakloop();
					return;
				}
				
				System.out.println("\nPacket #" + i++);

				packet.peer(buffer);

				scanner.scan(packet, JProtocol.ETHERNET_ID);
				dumpPacket(packet);
			}

		}, "");

		long end = System.currentTimeMillis();

		System.out.printf("time=%d ms\n", (end - start));

		pcap.close();
	}

	JHeader.State headerInfo = new JHeader.State();

	Ethernet ethernet = new Ethernet();

	Ip4 ip4 = new Ip4();

	Udp udp = new Udp();

	Tcp tcp = new Tcp();

	L2TP l2tp = new L2TP();
	PPP ppp = new PPP();

	Payload payload = new Payload();

	private void dumpPacket(JPacket packet) {

		int count = packet.getHeaderCount();

		for (int i = 0; i < count; i++) {
			packet.getState().peerHeaderByIndex(i, headerInfo);
			int id = headerInfo.getId();
			JProtocol protocol = JProtocol.valueOf(id);

			System.out.print(protocol.toString() + headerInfo.toString());

			// System.out.printf("#%d = %s(%d)\n", i, JProtocol.valueOf(id), id);
			switch (id) {
				case JProtocol.ETHERNET_ID:
					packet.getHeaderByIndex(i, ethernet);
					System.out.println(" dst="
					    + PcapUtils.asString(ethernet.destination()) + " src="
					    + PcapUtils.asString(ethernet.source()) + " type="
					    + ethernet.type());
					break;

				case JProtocol.IP4_ID:
					packet.getHeaderByIndex(i, ip4);
					System.out.println(" type=" + ip4.type());
					break;

				case JProtocol.UDP_ID:
					packet.getHeaderByIndex(i, udp);
					System.out.println(" src=" + udp.source() + " dst="
					    + udp.destination());
					break;

				case JProtocol.L2TP_ID:
					packet.getHeaderByIndex(i, l2tp);
					System.out.printf(" flags=0x%X T-flag=%s\n", l2tp.flags(),
					    (l2tp.flags() & L2TP.FLAG_T) != 0);
					break;

				case JProtocol.PPP_ID:
					packet.getHeaderByIndex(i, ppp);
					System.out.printf(" protocol=%d 0x%X\n", ppp.protocol(), ppp.protocol());
					break;

				default:
					System.out.println();
					break;
			}
		}
	}
}
