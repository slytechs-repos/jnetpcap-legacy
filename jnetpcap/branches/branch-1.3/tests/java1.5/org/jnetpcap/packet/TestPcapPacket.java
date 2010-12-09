/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.packet;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import junit.framework.TestCase;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.protocol.lan.Ethernet;

// TODO: Auto-generated Javadoc
/**
 * The Class TestPcapPacket.
 */
public class TestPcapPacket
    extends TestCase {

	/** The packet. */
	private PcapPacket packet;

	/** The packet2. */
	private PcapPacket packet2;

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

	/**
	 * Test get total size.
	 */
	public final void testGetTotalSize() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		int size = packet.getTotalSize();
		assertTrue("Low bounds " + size, size > packet.size() + PcapHeader.sizeof()
		    + PcapPacket.State.sizeof(1));
		assertTrue("High bounds " + size, size < packet.size()
		    + PcapHeader.sizeof() + PcapPacket.State.sizeof(20));
	}

	/**
	 * Test get total size null ptr.
	 */
	public final void testGetTotalSizeNullPtr() {
		packet = new PcapPacket(Type.POINTER);

		try {
			packet.getTotalSize();
			fail("expected null ptr on unitilized packet");
		} catch (NullPointerException e) {
			// expected
		}
	}

	/**
	 * Test pcap packet type.
	 */
	public final void testPcapPacketType() {
		packet = new PcapPacket(Type.POINTER);

		assertFalse("packet data", packet.isInitialized());
		assertFalse("packet state", packet.getState().isInitialized());
		assertFalse("pcap header", packet.getCaptureHeader().isInitialized());
	}

	/**
	 * Test pcap packet int.
	 */
	public final void testPcapPacketInt() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(2 * 1024);
		packet.transferStateAndDataTo(packet2);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.getState().size(), packet2.getState().size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());
	}

	/**
	 * Test pcap packet int underflow.
	 */
	public final void testPcapPacketIntUnderflow() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(10);
		packet.transferStateAndDataTo(packet2);

		assertTrue("memory was not reallocated",
		    packet2.getAllocatedMemorySize() > 10); // Reallocated

	}

	/**
	 * Test pcap packet int int.
	 */
	public final void testPcapPacketIntInt() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(packet.size(), packet.getHeaderCount());

		assertEquals(packet.getTotalSize(), packet2.getAllocatedMemorySize());
	}

	/**
	 * Test pcap packet int int underflow.
	 */
	public final void testPcapPacketIntIntUnderflow() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(10, 1);
		packet.transferStateAndDataTo(packet2);

		assertTrue("memory was not reallocated",
		    packet2.getAllocatedMemorySize() > 10); // Reallocated

	}

	/**
	 * Test pcap packet byte buffer direct.
	 */
	public final void testPcapPacketByteBufferDirect() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		ByteBuffer b = ByteBuffer.allocateDirect(packet.getTotalSize());
		packet.transferStateAndDataTo(b);
		b.flip();

		packet2 = new PcapPacket(b);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
	}
	
	/**
	 * Test pcap packet byte buffer array.
	 */
	public final void testPcapPacketByteBufferArray() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);
		
		ByteBuffer b = ByteBuffer.allocate(packet.getTotalSize());
		packet.transferStateAndDataTo(b);
		b.flip();

		packet2 = new PcapPacket(b);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
	}


	/**
	 * Test pcap packet byte buffer overflow.
	 */
	public final void testPcapPacketByteBufferOverflow() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		ByteBuffer b = ByteBuffer.allocateDirect(packet.getTotalSize() - 1);

		try {
			packet.transferStateAndDataTo(b);
			fail("expected undeflow exception");
		} catch (BufferOverflowException e) {
			// OK
		} catch (Exception e) {
			fail("expected overflow exception but got " + e.getClass().getSimpleName());
		}
	}

	/**
	 * Test pcap packet j buffer.
	 */
	public final void testPcapPacketJBuffer() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		JBuffer b = new JBuffer(packet.getTotalSize());
		packet.transferStateAndDataTo(b);

		packet2 = new PcapPacket(b);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
	}

	/**
	 * Test pcap packet pcap packet.
	 */
	public final void testPcapPacketPcapPacket() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(packet);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
	}

	/**
	 * Test get capture header.
	 */
	public final void testGetCaptureHeader() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		JCaptureHeader header = packet.getCaptureHeader();

		assertEquals(1075238237, header.seconds());
		assertEquals(192611000, header.nanos());
		assertEquals(114, header.caplen());
		assertEquals(114, header.wirelen());
		assertEquals(1075238237192L, header.timestampInMillis());
	}

	/**
	 * Test transfer to pcap packet.
	 */
	public final void testTransferToPcapPacket() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(Type.POINTER);
		packet.transferStateAndDataTo(packet2);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
	}
	
	/**
	 * Test pcap packet byte array.
	 */
	public final void testPcapPacketByteArray() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);
		
		byte[] b = new byte[packet.getTotalSize()];
		packet.transferStateAndDataTo(b);

		packet2 = new PcapPacket(b);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
		
	}
	
	/**
	 * Test pcap packet pcap header j buffer.
	 */
	public final void testPcapPacketPcapHeaderJBuffer() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);
		

		packet2 = new PcapPacket(packet.getCaptureHeader(), (JBuffer) packet);

		assertEquals(packet.size(), packet2.size());
//		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
		
	}
	
	/**
	 * Test pcap header.
	 */
	public final void testPcapHeader() {
		JBuffer buffer = new JBuffer(VariousInMemoryPackets.PACKET_1); // Allocate buffer of 128 bytes
		PcapHeader hdr = new PcapHeader(buffer.size(), buffer.size());
		PcapPacket packet = new PcapPacket(JMemory.POINTER);
		
		packet.peer(buffer);
		packet.getCaptureHeader().peerTo(hdr, 0);
		
		packet.scan(Ethernet.ID);
		
		System.out.println(packet);
		
	}

}
