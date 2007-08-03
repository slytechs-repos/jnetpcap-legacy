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
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import junit.textui.TestRunner;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestPcapJNI
    extends TestCase {
	
	private static final Log logger = LogFactory.getLog(TestPcapJNI.class);

	private final static String device = "\\Device\\NPF_{BC81C4FC-242F-4F1C-9DAD-EA9523CC992D}";

	private final static String fname = "tests/test-l2tp.pcap";

	private static final int OK = 0;

	/**
	 * Command line launcher to run the jUnit tests cases in this test class.
	 * 
	 * @param args
	 *         -h for help
	 */
	public static void main(String[] args) {
		if (args.length == 1 && "-h".equals(args[0])) {
			System.out.println(
					"Usage: java -jar jnetpcap.jar [-h]\n" +
					"  -h  This help message\n" +
					"   (No other command line options are supported.)\n" +
					"----------------------------------------------------------------\n\n" +
					"The 'main' method invoked here, runs several dozen jUnit tests\n" +
					"which test the functionality of this jNetPcap library.\n" +
					"The tests are actual excersizes using native libpcap\n" +
					"library linked with 'jnetpcap.dll' or 'libjnetpcap.so' on\n" +
					"unix systems.\n\n" +
					"If you are having trouble linking the native library and get\n" +
					"'UnsatisfiedLinkError', which means java is not finding the\n" +
					"library, here are a few pointers:\n\n" +
					"Java's native library loader DOES NOT USE CLASSPATH variable\n" +
					"to locate native libraries. Each operating system uses different\n" +
					"algorithm to locate files, as described below. You can always\n" +
					"force java to look for native library with Java VM command\n" +
					"line option 'java -Djava.library.path=lib' where lib is\n" +
					"a directory where 'jnetpcap.dll' or 'libjnetpcap.so' resides\n" +
					"relative to the installation directory of jNetStream package.\n" +
					"Or replace lib with the directory where you have installed the\n" +
					"library.\n\n" +
					"On Win32 systems:\n" +
					"  Windows systems use /windows and /windows/system32 folder\n" +
					"  to search for jnetpcap.dll. Also the 'PATH' variable, the same\n" +
					"  one used to specify executable commands, is used as well.\n\n" +
					"On Unix systems:\n" +
					"  All unix systems use the standard 'LD_LIBRARY_PATH' variable.\n\n" +
					"Of course as mentioned earlier, to override this behaviour use\n" +
					"the '-Djava.library.path=' directory, to force java to look in\n" +
					"that particular directory. Do not set the path which includes the\n" +
					"name of the library itself, just the directory to search in.\n\n" +
					"Final note, native librariers can not be loaded from jar files.\n" +
					"You have to extract it to a physical directory if you want java to\n" +
					"load it. This was done purposely by Sun for security reasons.");
			
			return;
		}
		logger.info("Running jNetPcap jUnit tests cases.");

		TestRunner.main(new String[] { "org.jnetpcap.TestPcapJNI" });

	}

	private StringBuilder errbuf;

	/**
	 * @throws java.lang.Exception
	 */
	protected void setUp() throws Exception {

		errbuf = new StringBuilder();
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

				// System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
				// .toString(), new Date(seconds * 1000).toString(), caplen, len,
				// buffer.capacity());

			}

		};

		pcap.dispatch(10, handler, "Hello");

		pcap.close();
	}

	/**
	 * @throws java.lang.Exception
	 */
	protected void tearDown() throws Exception {
		errbuf = null;
	}

	public void testCompileNoPcapNullPtrHandling() {
		try {
			Pcap.compileNoPcap(1, 1, null, null, 1, 1);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		}
	}

	public void testCompileNullPtrHandling() {
		Pcap pcap = Pcap.openOffline(fname, errbuf);
		try {
			pcap.compile(null, null, 1, 0);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		} finally {
			pcap.close();
		}
	}

	public void testDataLinkNameToValNullPtrHandling() {
		try {
			Pcap.datalinkNameToVal(null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		}
	}

	public void testDatalinkNameToValue() {
		assertEquals(1, Pcap.datalinkNameToVal("EN10MB"));
	}

	public void testDatalinkValueToDescription() {
		assertEquals("Ethernet", Pcap.datalinkValToDescription(1));

	}

	public void testDatalinkValueToName() {
		assertEquals("EN10MB", Pcap.datalinkValToName(1));

	}

	public void testDispatchNullPtrHandling() {
		Pcap pcap = Pcap.openOffline(fname, errbuf);
		try {
			pcap.dispatch(1, null, "");
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		} finally {
			pcap.close();
		}
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

				// System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
				// .toString(), new Date(seconds * 1000).toString(), caplen, len,
				// buffer.capacity());
			}
		};

		assertEquals(OK, pcap.setFilter(bpf));
		assertEquals(OK, pcap.loop(10, handler, str));

		Pcap.freecode(bpf);

		pcap.close();
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

	public void testFindAllDevs() {
		List<PcapIf> devs = new ArrayList<PcapIf>(); // List filled in by
		// findAllDevs

		int r = Pcap.findAllDevs(devs, errbuf);
		assertEquals(errbuf.toString(), 0, r);
		assertFalse(devs.isEmpty());
		assertEquals(2, devs.size());

		// System.out.println(devs);
	}

	public void testFindAllDevsNullPtrHandling() {
		try {
			Pcap.findAllDevs(null, null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		}
	}

	public void testFreeAllDevsNullPtrHandling() {
		try {
			Pcap.freeAllDevs(null, null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		}
	}

	public void testFreeCodeNullPtrHandling() {
		try {
			Pcap.freecode(null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		}
	}

	public void testGetNonBlockNullPtrHandling() {
		Pcap pcap = Pcap.openOffline(fname, errbuf);
		try {
			pcap.getNonBlock(null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		} finally {
			pcap.close();
		}
	}

	public void testLibVersion() {
		assertNotNull(Pcap.libVersion());
	}

	public void testLoopNullPtrHandling() {
		Pcap pcap = Pcap.openOffline(fname, errbuf);
		try {
			pcap.loop(1, null, null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		} finally {
			pcap.close();
		}
	}

	public void testNextExNullPtrHandling() {
		Pcap pcap = Pcap.openOffline(fname, errbuf);
		try {
			pcap.nextEx(null, null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		} finally {
			pcap.close();
		}
	}

	public void testNextNullPtrHandling() {
		Pcap pcap = Pcap.openOffline(fname, errbuf);
		try {
			pcap.next(null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		} finally {
			pcap.close();
		}
	}

	public void testOpenDeadAndClose() {

		Pcap pcap = Pcap.openDead(1, 10000); // DLT, SNAPLEN
		assertNotNull(pcap);

		pcap.close();
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

	public void testOpenLiveAndLoopWithBreakloop() {

		Pcap pcap = Pcap.openLive(device, 10000, 1, 60 * 1000, errbuf);
		assertNotNull(pcap);

		PcapHandler handler = new PcapHandler() {

			public void nextPacket(Object user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

				// System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
				// .toString(), new Date(seconds * 1000).toString(), caplen, len,
				// buffer.capacity());

			}

		};

		pcap.breakloop(); // Should cause it to exit immediately
		assertEquals(
		    "Error code does not indicate breakloop interrupted the loop when it should have",
		    -2, pcap.loop(10, handler, "Hello"));

		pcap.close();
	}

	public void testOpenOfflineAndClose() {

		Pcap pcap = Pcap.openOffline(fname, errbuf);
		assertNotNull(pcap);

		PcapHandler handler = new PcapHandler() {

			public void nextPacket(Object user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

				// System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
				// .toString(), new Date(seconds * 1000).toString(), caplen, len,
				// buffer.capacity());

			}

		};

		assertEquals("Expected to receive exactly 10 packets", 10, pcap.dispatch(
		    10, handler, "Hello"));
		pcap.close();
	}

	public void testOpenOfflineAndLoop() {

		Pcap pcap = Pcap.openOffline(fname, errbuf);
		assertNotNull(pcap);

		PcapHandler handler = new PcapHandler() {

			public void nextPacket(Object user, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {

				// System.out.printf("%s, ts=%s caplen=%d len=%d capacity=%d\n", user
				// .toString(), new Date(seconds * 1000).toString(), caplen, len,
				// buffer.capacity());

			}

		};

		assertEquals(OK, pcap.loop(10, handler, "Hello"));

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

	public void testPcapDLTAndDoNameToValueComparison() {
		int match = 0; // counts how many constants compared OK

		for (PcapDLT c : PcapDLT.values()) {
			int dlt = c.value;
			String libName = Pcap.datalinkValToName(dlt);
			if (libName == null) {
				// System.out.printf("no dlt: dlt=%d enum=%s\n", dlt, c.toString());
				continue;
			}

			if (libName.equals(c.name())) {
				match++;

				// System.out.printf("matched: dlt=%d enum=%s pcap=%s desc=%s\n", dlt, c
				// .toString(), libName, c.description);
			} else {
				// System.out.printf("unmatched: dlt=%d enum=%s pcap=%s desc=%s\n", dlt,
				// c
				// .toString(), libName, c.description);
			}
		}

		// System.out.println("Have " + match + " matches out of "
		// + PcapDLT.values().length);

		assertTrue(
		    "Something is wrong, most constants should match native pcap library",
		    match > 20);

		// for (int dlt = 0; dlt < 100; dlt ++) {
		// String libName = Pcap.datalinkValToName(dlt);
		// PcapDLT c = PcapDLT.valueOf(dlt);
		//			
		// if (c == null && libName != null) {
		// System.out.printf("We don't have dlt=%d pcap=%s\n", dlt, libName);
		// }
		// }
	}

	public void testPcapOpenLiveNullPtrHandling() {
		try {
			Pcap.openLive(null, 1, 1, 1, null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		}
	}

	public void testPcapOpenOfflineNullPtrHandling() {
		try {
			Pcap.openOffline(null, null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		}
	}

	public void testSetAndGetNonblock() {
		Pcap pcap = Pcap.openLive(device, 10000, 1, 60 * 1000, errbuf);
		assertNotNull(pcap);

		assertEquals(OK, pcap.getNonBlock(errbuf));

		pcap.close();
	}

	public void testSetFilterNullPtrHandling() {
		Pcap pcap = Pcap.openOffline(fname, errbuf);
		try {
			pcap.setFilter(null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		} finally {
			pcap.close();
		}
	}

	public void testSetNonBlockNullPtrHandling() {
		Pcap pcap = Pcap.openOffline(fname, errbuf);
		try {
			pcap.setNonBlock(1, null);
			fail("Expected a NULL pointer exception.");
		} catch (NullPointerException e) {
			// OK
		} finally {
			pcap.close();
		}
	}
}
