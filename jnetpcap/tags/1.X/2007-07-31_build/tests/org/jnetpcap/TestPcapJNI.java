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

import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.Date;

import junit.framework.TestCase;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapPktbuffer;
import org.jnetpcap.PcapPkthdr;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestPcapJNI
    extends TestCase {

	private StringBuilder errbuf;

	private final static String device = "\\Device\\NPF_{BC81C4FC-242F-4F1C-9DAD-EA9523CC992D}";

	private final static String fname = "tests/test-l2tp.pcap";
	
	private static final int OK = 0;

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
		errbuf = null;
	}

	public void testErrbuf() throws SocketException, InterruptedException {

		// Test using a bogus device name that's sure to fail
		errbuf.append("def"); // Set dummy message and it should be replaced
		Pcap pcap = Pcap.openLive("abc", 101, 1, 60, errbuf);
		assertNull(pcap);

		assertFalse("Our pre-initialized error message should have been cleared",
		    "def".equals(errbuf.toString()));

		assertTrue("Error buffer should contain an error message",
		    errbuf.length() != 0);
	}

	public void testOpenLiveAndDatalinkAndClose() throws SocketException,
	    InterruptedException {

		Pcap pcap = Pcap.openLive(device, 101, 1, 60, errbuf);

		// Physical field initialized from JNI space
		assertFalse("0".equals(pcap.toString()));

		// Check linklayer 1 is for DLT_EN10MB
		assertEquals(1, pcap.datalink());

		pcap.close();

		try {
			pcap.close();
			fail();
		} catch (IllegalStateException e) {
			// Expecting this exception on second call to close()
		}
	}

	/**
	 * Test disabled, as it requires live packets to capture. To enable the test
	 * just rename the method, by removing the prefix SKIP. Then make sure there
	 * are live packets to be captured.
	 */
	public void SKIPtestOpenLiveAndDispatch() {

		Pcap pcap = Pcap.openLive(device, 10000, 1, 60 * 1000, errbuf);
		assertNotNull(pcap);

		PcapHandler handler = new PcapHandler() {

			public void nextPacket(Object user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

//				System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
//				    .toString(), new Date(seconds * 1000).toString(), caplen, len,
//				    buffer.capacity());

			}

		};

		pcap.dispatch(10, handler, "Hello");

		pcap.close();
	}

	public void testOpenOfflineAndLoop() {

		Pcap pcap = Pcap.openOffline(fname, errbuf);
		assertNotNull(pcap);

		PcapHandler handler = new PcapHandler() {

			public void nextPacket(Object user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

//				System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
//				    .toString(), new Date(seconds * 1000).toString(), caplen, len,
//				    buffer.capacity());

			}

		};

		assertEquals(OK, pcap.loop(10, handler, "Hello"));

		pcap.close();
	}

	public void testOpenLiveAndLoopWithBreakloop() {

		Pcap pcap = Pcap.openLive(device, 10000, 1, 60 * 1000, errbuf);
		assertNotNull(pcap);

		PcapHandler handler = new PcapHandler() {

			public void nextPacket(Object user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

//				System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
//				    .toString(), new Date(seconds * 1000).toString(), caplen, len,
//				    buffer.capacity());

			}

		};

		pcap.breakloop(); // Should cause it to exit immediately
		assertEquals(
		    "Error code does not indicate breakloop interrupted the loop when it should have",
		    -2, pcap.loop(10, handler, "Hello"));

		pcap.close();
	}

	public void testOpenDeadAndClose() {

		Pcap pcap = Pcap.openDead(1, 10000); // DLT, SNAPLEN
		assertNotNull(pcap);

		pcap.close();
	}

	public void testOpenOfflineAndClose() {

		Pcap pcap = Pcap.openOffline(fname, errbuf);
		assertNotNull(pcap);

		PcapHandler handler = new PcapHandler() {

			public void nextPacket(Object user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

//				System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
//				    .toString(), new Date(seconds * 1000).toString(), caplen, len,
//				    buffer.capacity());

			}

		};

		assertEquals("Expected to receive exactly 10 packets", 10, pcap.dispatch(
		    10, handler, "Hello"));
		pcap.close();
	}

	public void testSetAndGetNonblock() {
		Pcap pcap = Pcap.openLive(device, 10000, 1, 60 * 1000, errbuf);
		assertNotNull(pcap);

		assertEquals(OK, pcap.getNonBlock(errbuf));

		pcap.close();
	}

	public void testOpenOfflineAndNext() {

		Pcap pcap = Pcap.openOffline(fname, errbuf);
		assertNotNull(pcap);
		PcapPkthdr hdr = new PcapPkthdr();

		ByteBuffer buffer = pcap.next(hdr);

		assertEquals(114, buffer.capacity()); // length of the packet should match
		assertEquals(114, hdr.getCaplen()); // Should match within the header too
		assertEquals(114, hdr.getLen()); // Should match within the header too

		// System.out.println(new Date(hdr.getSeconds() * 1000).toString());

		pcap.close();
	}

	public void testOpenOfflineAndNextEx() {

		Pcap pcap = Pcap.openOffline(fname, errbuf);
		assertNotNull(pcap);
		PcapPkthdr hdr = new PcapPkthdr();
		PcapPktbuffer buf = new PcapPktbuffer();

		int r = pcap.nextEx(hdr, buf);
		assertEquals(1, r);
		assertNotNull(buf.getBuffer());

		assertEquals(114, buf.getBuffer().capacity()); // length of the packet
		// should match
		assertEquals(114, hdr.getCaplen()); // Should match within the header too
		assertEquals(114, hdr.getLen()); // Should match within the header too

		// System.out.println(new Date(hdr.getSeconds() * 1000).toString());

		pcap.close();
	}
	
	public void testDatalinkValueToName() {
		assertEquals("EN10MB", Pcap.datalinkValToName(1));

	}
	
	public void testDatalinkNameToValue() {
		assertEquals(1, Pcap.datalinkNameToVal("EN10MB"));
	}
	
	public void testDatalinkValueToDescription() {
		assertEquals("Ethernet", Pcap.datalinkValToDescription(1));

	}
	
	public void testLibVersion() {
		assertNotNull(Pcap.libVersion());
	}
	
	public void testFindAllDevs() {
		PcapIf devs = new PcapIf();
		
		int r = Pcap.findAllDevs(devs, errbuf);
		assertEquals(errbuf.toString(), 0, r);
		assertNotNull(devs.getNext());
		
//		System.out.println(devs.getNext().toString());		
//		System.out.println(devs.toList());
	}
	
	public void testFilterCompileNoPcapAndAccessors() {
		PcapBpfProgram bpf = new PcapBpfProgram();
		
		// Check state protection when object not ready yet. 
		try {
			bpf.getInstructionCount();
			fail("Should have generated an illegal state exception");
		} catch (IllegalStateException e) {
			// OK
		}
		
		String str = "host 192.168.1.1";
		
		int r = Pcap.compileNoPcap(1024, 1, bpf, str, 0, 0);
		assertEquals(OK, r);
		
		assertEquals(26, bpf.getInstructionCount());
		assertEquals(120259084320L, bpf.getInstruction(10));
		
		// Boundary checks
		try {
			bpf.getInstruction(-10);
			fail("Failed to generate exception on low index boundary");
		} catch (IndexOutOfBoundsException e) {
			// OK
		}
		
		// Boundary checks
		try {
			bpf.getInstruction(26);
			fail("Failed to generate exception on upper index boundary");
		} catch (IndexOutOfBoundsException e) {
			// OK
		}
		
		Pcap.freecode(bpf);
	}
	
	public void testFilterCompileAndSetFilter() {
		PcapBpfProgram bpf = new PcapBpfProgram();
		String str = "host 192.168.101";
		
		Pcap pcap = Pcap.openOffline(fname, errbuf);
		assertNotNull(pcap);
		
		int r = pcap.compile(bpf, str, 0, 0);
		assertEquals(pcap.getErr(), 0, r);
		
		
		PcapHandler handler = new PcapHandler() {
			public void nextPacket(Object user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

//				System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
//				    .toString(), new Date(seconds * 1000).toString(), caplen, len,
//				    buffer.capacity());
			}
		};

		assertEquals(OK, pcap.setFilter(bpf));
		assertEquals(OK, pcap.loop(10, handler, str));
		
		Pcap.freecode(bpf);
		
		pcap.close();
	}
}
