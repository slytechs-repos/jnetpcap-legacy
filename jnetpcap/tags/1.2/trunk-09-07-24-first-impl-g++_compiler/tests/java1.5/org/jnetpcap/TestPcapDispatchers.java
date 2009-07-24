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
package org.jnetpcap;

import java.nio.ByteBuffer;

import junit.framework.TestCase;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestPcapDispatchers
    extends TestCase {

	private final static int COUNT = 3;

	private StringBuilder errbuf = new StringBuilder();

	private Pcap pcap;

	private final static String TEST_AFS = "tests/test-afs.pcap";

	private Pcap open(String file) {
		return Pcap.openOffline(file, errbuf);
	}

	private static class Counter {
		public long count = 0;

		public long ts = System.currentTimeMillis();

		public void inc() {
			if (++count % 100000 == 0) {
				long delta = System.currentTimeMillis() - ts;
				System.out.printf("100K #%d @ %s, " +
						"mem+%d, mem-%d mem=%d, calls+%d calls-%d\n", 
						(count / 100000), 
						FormatUtils.formatTimeInMillis(delta),
						(int)JMemory.totalAllocated(),
						JMemory.totalDeAllocated(),
						JMemory.totalActiveAllocated(),
						JMemory.totalAllocateCalls(),
						JMemory.totalDeAllocateCalls());

				ts = System.currentTimeMillis();
				// System.gc();
			}
		}
	}

	private final static Counter COUNTER = new Counter();

	private void loop(String file, JPacketHandler<Counter> handler) {
		pcap = open(file);
		assertEquals(Pcap.OK, pcap.loop(Pcap.LOOP_INFINATE, handler, COUNTER));

		pcap.close();
		pcap = null;
	}

	private void dispatch(String file, JPacketHandler<Counter> handler) {
		pcap = open(file);
		assertEquals(Pcap.OK, pcap.dispatch(Pcap.DISPATCH_BUFFER_FULL, handler,
		    COUNTER));

		pcap.close();
		pcap = null;
	}

	private void loop(String file, PcapPacketHandler<Counter> handler) {
		pcap = open(file);
		assertEquals(Pcap.OK, pcap.loop(Pcap.LOOP_INFINATE, handler, COUNTER));

		pcap.close();
		pcap = null;
	}

	@SuppressWarnings("deprecation")
  private void dispatch(String file, PcapPacketHandler<Counter> handler) {
		pcap = open(file);
		assertEquals(Pcap.OK, pcap.dispatch(Pcap.DISPATCH_BUFFER_FULL, handler,
		    COUNTER));

		pcap.close();
		pcap = null;
	}

	private void loop(String file, JBufferHandler<Counter> handler) {
		pcap = open(file);
		assertEquals(Pcap.OK, pcap.loop(Pcap.LOOP_INFINATE, handler, COUNTER));

		pcap.close();
		pcap = null;
	}

	private void dispatch(String file, JBufferHandler<Counter> handler) {
		pcap = open(file);
		assertEquals(Pcap.OK, pcap.dispatch(Pcap.DISPATCH_BUFFER_FULL, handler,
		    COUNTER));

		pcap.close();
		pcap = null;
	}

	private void loop(String file, ByteBufferHandler<Counter> handler) {
		pcap = open(file);
		assertEquals(Pcap.OK, pcap.loop(Pcap.LOOP_INFINATE, handler, COUNTER));

		pcap.close();
		pcap = null;
	}

	private void dispatch(String file, ByteBufferHandler<Counter> handler) {
		pcap = open(file);
		assertEquals(Pcap.OK, pcap.dispatch(Pcap.DISPATCH_BUFFER_FULL, handler,
		    COUNTER));

		pcap.close();
		pcap = null;
	}

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
		if (pcap != null) {
			pcap.close();
			pcap = null;
		}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.ByteBufferHandler, java.lang.Object)}.
	 */
	public final void testDispatchIntByteBufferHandlerOfTTLoop() {
		for (int i = 0; i < COUNT; i++) {
			loop(TEST_AFS, new ByteBufferHandler<Counter>() {
				public void nextPacket(
				    PcapHeader header,
				    ByteBuffer packet,
				    Counter counter) {
					counter.inc();

					ByteBuffer.allocateDirect(packet.capacity()).put(packet);
				}
			});
		}
	}

	public final void testDispatchIntByteBufferHandlerOfTTDispatch() {
		for (int i = 0; i < COUNT; i++) {
			dispatch(TEST_AFS, new ByteBufferHandler<Counter>() {
				public void nextPacket(
				    PcapHeader header,
				    ByteBuffer packet,
				    Counter counter) {
					counter.inc();
					ByteBuffer.allocateDirect(packet.capacity()).put(packet);
				}
			});
		}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#dispatch(int, int, org.jnetpcap.packet.JPacketHandler, java.lang.Object)}.
	 */
	public final void testDispatchIntIntJPacketHandlerOfTTLoop() {
		for (int i = 0; i < COUNT; i++) {
			loop(TEST_AFS, new JPacketHandler<Counter>() {
				public void nextPacket(JPacket packet, Counter counter) {
					counter.inc();
					new JMemoryPacket(packet.size()).transferStateAndDataFrom(packet);
				}
			});
		}
	}

	public final void testDispatchIntIntJPacketHandlerOfTTDispatch() {
		for (int i = 0; i < COUNT; i++) {
			dispatch(TEST_AFS, new JPacketHandler<Counter>() {
				public void nextPacket(JPacket packet, Counter counter) {
					counter.inc();
					new JMemoryPacket(packet.size()).transferStateAndDataFrom(packet);
				}
			});
		}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#dispatch(int, int, org.jnetpcap.packet.PcapPacketHandler, java.lang.Object)}.
	 */
	public final void testDispatchIntIntPcapPacketHandlerOfTTLoop() {
		for (int i = 0; i < COUNT; i++) {
			loop(TEST_AFS, new PcapPacketHandler<Counter>() {
				public void nextPacket(PcapPacket packet, Counter counter) {
					counter.inc();

					new PcapPacket(packet);
				}
			});
		}
	}

	public final void testDispatchIntIntPcapPacketHandlerOfTTDispatch() {
		for (int i = 0; i < COUNT; i++) {
			dispatch(TEST_AFS, new PcapPacketHandler<Counter>() {
				public void nextPacket(PcapPacket packet, Counter counter) {
					counter.inc();
					new PcapPacket(packet);
				}
			});
		}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.JBufferHandler, java.lang.Object)}.
	 */
	public final void testDispatchIntJBufferHandlerOfTTLoop() {
		for (int i = 0; i < COUNT; i++) {
			loop(TEST_AFS, new JBufferHandler<Counter>() {
				public void nextPacket(
				    PcapHeader header,
				    JBuffer packet,
				    Counter counter) {
					counter.inc();
					new JBuffer(packet.size()).transferFrom(packet);
				}
			});
		}
	}

	public final void testDispatchIntJBufferHandlerOfTTDispatch() {
		for (int i = 0; i < COUNT; i++) {
			dispatch(TEST_AFS, new JBufferHandler<Counter>() {
				public void nextPacket(
				    PcapHeader header,
				    JBuffer packet,
				    Counter counter) {
					counter.inc();
					new JBuffer(packet.size()).transferFrom(packet);
				}
			});
		}
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.packet.JPacketHandler, java.lang.Object)}.
	 */
	public final void _testDispatchIntJPacketHandlerOfTT() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.packet.PcapPacketHandler, java.lang.Object)}.
	 */
	public final void _testDispatchIntPcapPacketHandlerOfTT() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#loop(int, org.jnetpcap.ByteBufferHandler, java.lang.Object)}.
	 */
	public final void _testLoopIntByteBufferHandlerOfTT() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#loop(int, int, org.jnetpcap.packet.JPacketHandler, java.lang.Object)}.
	 */
	public final void _testLoopIntIntJPacketHandlerOfTT() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#loop(int, int, org.jnetpcap.packet.PcapPacketHandler, java.lang.Object)}.
	 */
	public final void _testLoopIntIntPcapPacketHandlerOfTT() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#loop(int, org.jnetpcap.JBufferHandler, java.lang.Object)}.
	 */
	public final void _testLoopIntJBufferHandlerOfTT() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#loop(int, org.jnetpcap.packet.JPacketHandler, java.lang.Object)}.
	 */
	public final void _testLoopIntJPacketHandlerOfTT() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for
	 * {@link org.jnetpcap.Pcap#loop(int, org.jnetpcap.packet.PcapPacketHandler, java.lang.Object)}.
	 */
	public final void _testLoopIntPcapPacketHandlerOfTT() {
		fail("Not yet implemented");
	}

}
