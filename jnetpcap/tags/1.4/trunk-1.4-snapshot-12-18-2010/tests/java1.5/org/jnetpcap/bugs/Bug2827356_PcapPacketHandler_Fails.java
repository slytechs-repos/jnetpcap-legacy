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
package org.jnetpcap.bugs;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.TestUtils;

/**
 * Once in a while an exception will be thrown by the scanner. Seems like
 * invalid header is matched and causes the scanner to reach out of bounds.
 * <p>
 * Discussion thread: http://jnetpcap.com/node/352
 * </p>
 * The issue is in native method <code>validate_http</code> where status
 * values are incorrectly returned. Protocol ID vs. INVALID are not returned
 * properly when http header is matched.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Bug2827356_PcapPacketHandler_Fails
    extends
    TestUtils {

	/**
	 * Test file containing 5 ICMP packets that fail decoding under this bug.
	 */
	public final static String SMALL_ICMP_FILE = "tests/test-small-imap.pcap";

	private Pcap pcap;

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() throws Exception {
		pcap = TestUtils.openOffline(SMALL_ICMP_FILE);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		pcap.close();
		pcap = null;
	}

	/**
   * Read special capture file with 5 ICMP packets that agravates this issue.
   * This method uses JBufferHandler, which does not fail on assertNotNull().
   * This method validates the libpcap wrapper part, since decoder/scanner is
   * not involved.
   */
  public void testValidateHttpJBufferPacketHandler() {
  
  	pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Pcap>() {
  
  		public void nextPacket(PcapHeader header, JBuffer buffer, Pcap user) {
  			assertNotNull(buffer);
  		}
  
  	}, pcap);
  }

	/**
	 * Read special capture file with 5 ICMP packets that agravates this issue.
	 * This method uses PcapPacketHandler, which fails assertNotNull(). This
	 * method checks the full-blown packet decoding capability.
	 */
	public void testValidateHttpPcapPacketHandler() {

		pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<Pcap>() {

			public void nextPacket(PcapPacket packet, Pcap user) {
				assertNotNull(packet);

				System.out.println(packet);
			}

		}, pcap);
	}

	/**
	 * Read special capture file with 5 ICMP packets that agravates this issue.
	 * This method uses JBufferHandler, which does not fail on assertNotNull().
	 * This method uses the low level handler (no decoding) and performs manual
	 * decoding of the buffer content. This method uses the default JPacket
	 * scanner that all JPacket.scan method use. PcapPacketHandler utilizes a
	 * different instance Scanner that a thread local global scanner.
	 */
	public void testValidateHttpJBufferPacketHandlerWithLocalPacketScanner() {

		pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Pcap>() {

			public void nextPacket(PcapHeader header, JBuffer buffer, Pcap pcap) {
				assertNotNull(buffer);

				final int id = JRegistry.mapDLTToId(pcap.datalink());

				PcapPacket packet = new PcapPacket(header, buffer);
				assertNotNull(packet);

				packet.scan(id);
			}

		}, pcap);
	}

	/**
	 * Read special capture file with 5 ICMP packets that agravates this issue.
	 * This method uses JBufferHandler, which does not fail on assertNotNull().
	 * This method uses the low level handler (no decoding) and performs manual
	 * decoding of the buffer content. This method uses the global (thread-local)
	 * scanner used by handlers.
	 */
	public void testValidateHttpJBufferPacketHandlerWithGlobalScanner() {

		pcap.loop(Pcap.LOOP_INFINITE, new JBufferHandler<Pcap>() {

			public void nextPacket(PcapHeader header, JBuffer buffer, Pcap pcap) {
				assertNotNull(buffer);

				final int id = JRegistry.mapDLTToId(pcap.datalink());

				PcapPacket packet = new PcapPacket(header, buffer);
				assertNotNull(packet);

				JScanner scanner = JScanner.getThreadLocal();
				scanner.scan(packet, id);
			}

		}, pcap);
	}

}
