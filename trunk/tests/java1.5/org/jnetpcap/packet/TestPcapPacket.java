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

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import junit.framework.TestCase;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory.Type;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestPcapPacket
    extends TestCase {

	private PcapPacket packet;

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
	 * Test method for {@link org.jnetpcap.packet.PcapPacket#getTotalSize()}.
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
	 * Test method for {@link org.jnetpcap.packet.PcapPacket#getTotalSize()}.
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
	 * Test method for
	 * {@link org.jnetpcap.packet.PcapPacket#PcapPacket(org.jnetpcap.nio.JMemory.Type)}.
	 */
	public final void testPcapPacketType() {
		packet = new PcapPacket(Type.POINTER);

		assertFalse("packet data", packet.isInitialized());
		assertFalse("packet state", packet.getState().isInitialized());
		assertFalse("pcap header", packet.getCaptureHeader().isInitialized());
	}

	/**
	 * Test method for {@link org.jnetpcap.packet.PcapPacket#PcapPacket(int)}.
	 */
	public final void testPcapPacketInt() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(2 * 1024);
		packet.transferTo(packet2);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.getState().size(), packet2.getState().size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());
	}

	public final void testPcapPacketIntUnderflow() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(10);
		packet.transferTo(packet2);

		assertTrue("memory was not reallocated",
		    packet2.getAllocatedMemorySize() > 10); // Reallocated

	}

	/**
	 * Test method for {@link org.jnetpcap.packet.PcapPacket#PcapPacket(int, int)}.
	 */
	public final void testPcapPacketIntInt() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(packet.size(), packet.getHeaderCount());

		assertEquals(packet.getTotalSize(), packet2.getAllocatedMemorySize());
	}

	public final void testPcapPacketIntIntUnderflow() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(10, 1);
		packet.transferTo(packet2);

		assertTrue("memory was not reallocated",
		    packet2.getAllocatedMemorySize() > 10); // Reallocated

	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.packet.PcapPacket#PcapPacket(java.nio.ByteBuffer)}.
	 * Reads a single packet out of a file, copies the packet image to a
	 * ByteBuffer then creates a second packet that reads the image from
	 * ByteBuffer. The image includes, PcapHeader, State and packet data.
	 */
	public final void testPcapPacketByteBufferDirect() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		ByteBuffer b = ByteBuffer.allocateDirect(packet.getTotalSize());
		packet.transferTo(b);
		b.flip();

		packet2 = new PcapPacket(b);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
	}
	
	public final void testPcapPacketByteBufferArray() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);
		
		ByteBuffer b = ByteBuffer.allocate(packet.getTotalSize());
		packet.transferTo(b);
		b.flip();

		packet2 = new PcapPacket(b);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
	}


	public final void testPcapPacketByteBufferOverflow() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		ByteBuffer b = ByteBuffer.allocateDirect(packet.getTotalSize() - 1);

		try {
			packet.transferTo(b);
			fail("expected undeflow exception");
		} catch (BufferOverflowException e) {
			// OK
		} catch (Exception e) {
			fail("expected overflow exception but got " + e.getClass().getSimpleName());
		}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.packet.PcapPacket#PcapPacket(org.jnetpcap.nio.JBuffer)}.
	 */
	public final void testPcapPacketJBuffer() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		JBuffer b = new JBuffer(packet.getTotalSize());
		packet.transferTo(b);

		packet2 = new PcapPacket(b);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.packet.PcapPacket#PcapPacket(org.jnetpcap.packet.PcapPacket)}.
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
	 * Test method for {@link org.jnetpcap.packet.PcapPacket#getCaptureHeader()}.
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
	 * Test method for
	 * {@link org.jnetpcap.packet.PcapPacket#transferTo(org.jnetpcap.packet.PcapPacket)}.
	 */
	public final void testTransferToPcapPacket() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);

		packet2 = new PcapPacket(Type.POINTER);
		packet.transferTo(packet2);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
	}
	
	public final void testPcapPacketByteArray() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);
		
		byte[] b = new byte[packet.getTotalSize()];
		packet.transferTo(b);

		packet2 = new PcapPacket(b);

		assertEquals(packet.size(), packet2.size());
		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
		
	}
	
	public final void testPcapPacketPcapHeaderJBuffer() {
		packet = TestUtils.getPcapPacket("tests/test-l2tp.pcap", 0);
		

		packet2 = new PcapPacket(packet.getCaptureHeader(), (JBuffer) packet);

		assertEquals(packet.size(), packet2.size());
//		assertEquals(packet.state.size(), packet2.state.size());
		assertEquals(packet.getCaptureHeader().size(), packet2.getCaptureHeader()
		    .size());

		// System.out.println(packet2.toString());
		
	}

}
