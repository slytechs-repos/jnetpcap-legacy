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

import java.nio.ByteBuffer;

import junit.framework.TestCase;

import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.header.Ethernet;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.packet.header.Ip6;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JHandlerTest
    extends TestCase implements ByteBufferHandler<String>,
    JBufferHandler<String>, JPacketHandler<String> {

	private Ethernet ethernet = new Ethernet();

	private Ip4 ip4 = new Ip4();

	private Ip6 ip6 = new Ip6();

	private PcapPacket packet = new PcapPacket(Type.POINTER);

	private JScanner scanner = new JScanner();

	private Pcap pcap;

	@Override
	protected void setUp() throws Exception {
		
		pcap = TestUtils.openOffline("tests/test-afs.pcap");
		assertNotNull(pcap);
	}

	@Override
	protected void tearDown() throws Exception {
		assertNotNull(pcap);
		pcap.close();
	}

	public void testJScannerHandler() {

		pcap.dispatch(2, JProtocol.ETHERNET_ID,
		    (JPacketHandler<String>) this, "JPacket - testcase");
	}

	public void testJBufferHandler() {

		pcap.dispatch(2, (JBufferHandler<String>) this, "JBuffer - testcase");
	}

	public void testPcapHandler() {

		pcap.dispatch(2, (ByteBufferHandler<String>) this,
		    "Pcap handler - testcase");
	}

	/**
	 * 
	 */
	public void nextPacket(PcapHeader pcapHdr, JBuffer jbuf, String user) {

		packet.peer(jbuf);
		scanner.scan(packet, Ethernet.ID);

		if (packet.hasHeader(ethernet)) {
			System.out.println("ethernet.dst=" + ethernet.destination());
		}

		if (packet.hasHeader(ip4)) {
			System.out.println("ip4.ver=" + ip4.version());
		}

		if (packet.hasHeader(ip6)) {
			System.out.println("ip4.ver=" + ip4.version());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JScannerHandler#nextPacket(org.jnetpcap.PcapHeader,
	 *      org.jnetpcap.packet.JPacket, java.lang.Object)
	 */
	public void nextPacket(JPacket packet, String user) {

		if (packet.hasHeader(ethernet)) {
			System.out.println("ethernet.dst=" + ethernet.destination());
		}

		if (packet.hasHeader(ip4)) {
			System.out.println("ip4.ver=" + ip4.version());
		}

		if (packet.hasHeader(ip6)) {
			System.out.println("ip4.ver=" + ip4.version());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.PcapHandler#nextPacket(java.lang.Object, long, int, int,
	 *      int, java.nio.ByteBuffer)
	 */
	public void nextPacket(PcapHeader header, ByteBuffer bytebuffer, String user) {

		try {
	    packet.peer(bytebuffer);
    } catch (PeeringException e) {
	    e.printStackTrace();
    }
		scanner.scan(packet, Ethernet.ID);

		if (packet.hasHeader(ethernet)) {
			System.out.println("ethernet.dst=" + ethernet.destination());
		}

		if (packet.hasHeader(ip4)) {
			System.out.println("ip4.ver=" + ip4.version());
		}

		if (packet.hasHeader(ip6)) {
			System.out.println("ip4.ver=" + ip4.version());
		}

	}
}
