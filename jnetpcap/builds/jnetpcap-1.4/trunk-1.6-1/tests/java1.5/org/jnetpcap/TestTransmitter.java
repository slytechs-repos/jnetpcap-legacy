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

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import junit.framework.TestCase;
import junit.textui.TestRunner;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class TestTransmitter
    extends TestCase {

	private final static String linux = "any";

	private final static String device = linux;

	private static final int OK = 0;

	private static final int snaplen = 64 * 1024;

	private static final int promisc = 1;

	private static final int oneSecond = 1000;

	/**
	 * Will generate HTTP traffic to a website. Use start() to start in a test
	 * method, and always put stop() in tearDown. Safe to call stop even when
	 * never started.
	 */
	private static final HttpTrafficGenerator gen = new HttpTrafficGenerator();

	private static File tmpFile;

	static {
		try {
			tmpFile = File.createTempFile("temp-", "-TestPcapJNI");
		} catch (IOException e) {
			tmpFile = null;
			System.err.println("Unable to initialize a temporary file");
		}

	}

	/**
	 * Command line launcher to run the jUnit tests cases in this test class.
	 * 
	 * @param args
	 *          -h for help
	 */
	public static void main(String[] args) {
		if (args.length == 1 && "-h".equals(args[0])) {
			System.out
			    .println("Usage: java -jar jnetpcap.jar [-h]\n"
			        + "  -h  This help message\n"
			        + "   (No other command line options are supported.)\n"
			        + "----------------------------------------------------------------\n\n"
			        + "The 'main' method invoked here, runs several dozen jUnit tests\n"
			        + "which test the functionality of this jNetPcap library.\n"
			        + "The tests are actual excersizes using native libpcap\n"
			        + "library linked with 'jnetpcap.dll' or 'libjnetpcap.so' on\n"
			        + "unix systems.\n\n"
			        + "If you are having trouble linking the native library and get\n"
			        + "'UnsatisfiedLinkError', which means java is not finding the\n"
			        + "library, here are a few pointers:\n\n"
			        + "Java's native library loader DOES NOT USE CLASSPATH variable\n"
			        + "to locate native libraries. Each operating system uses different\n"
			        + "algorithm to locate files, as described below. You can always\n"
			        + "force java to look for native library with Java VM command\n"
			        + "line option 'java -Djava.library.path=lib' where lib is\n"
			        + "a directory where 'jnetpcap.dll' or 'libjnetpcap.so' resides\n"
			        + "relative to the installation directory of jNetStream package.\n"
			        + "Or replace lib with the directory where you have installed the\n"
			        + "library.\n\n"
			        + "On Win32 systems:\n"
			        + "  Windows systems use /windows and /windows/system32 folder\n"
			        + "  to search for jnetpcap.dll. Also the 'PATH' variable, the same\n"
			        + "  one used to specify executable commands, is used as well.\n\n"
			        + "On Unix systems:\n"
			        + "  All unix systems use the standard 'LD_LIBRARY_PATH' variable.\n\n"
			        + "Of course as mentioned earlier, to override this behaviour use\n"
			        + "the '-Djava.library.path=' directory, to force java to look in\n"
			        + "that particular directory. Do not set the path which includes the\n"
			        + "name of the library itself, just the directory to search in.\n\n"
			        + "Final note, native librariers can not be loaded from jar files.\n"
			        + "You have to extract it to a physical directory if you want java to\n"
			        + "load it. This was done purposely by Sun for security reasons.");

			return;
		}

		TestRunner.main(new String[] { "org.jnetpcap.TestPcapJNI" });

	}

	private StringBuilder errbuf = new StringBuilder();

	@SuppressWarnings("deprecation")
	private final PcapHandler<?> doNothingHandler = new PcapHandler<Object>() {

		public void nextPacket(Object userObject, long seconds, int useconds,
		    int caplen, int len, ByteBuffer buffer) {
			// Do nothing handler
		}
	};

	/**
	 * @throws java.lang.Exception
	 */
	protected void setUp() throws Exception {

		errbuf = new StringBuilder();

		if (tmpFile.exists()) {
			assertTrue(tmpFile.delete());
		}

	}

	/**
	 * @throws java.lang.Exception
	 */
	public void tearDown() throws Exception {
	}

	/**
	 * This is a tricky test that must be disabled by default. We create a dummy
	 * packet all filled with 0xFF for 14 bytes which is the size of ethernet
	 * frame. This should produce a broadcast frame.
	 */
	public void testSendPacket() {

		Pcap pcap = Pcap.openLive("eth0", snaplen, 1, 10 * oneSecond, errbuf);
		assertNotNull(errbuf.toString(), pcap);

		byte[] a = new byte[14];
		Arrays.fill(a, (byte) 0xff);

		ByteBuffer b = ByteBuffer.wrap(a);

		if (pcap.sendPacket(b) != Pcap.OK) {
			fail(pcap.getErr());
		}

		pcap.close();

	}

	/**
	 * This is a tricky test that must be disabled by default. We create a dummy
	 * packet all filled with 0xFF for 14 bytes which is the size of ethernet
	 * frame. This should produce a broadcast frame.
	 */
	public void testInjectPacket() {

		Pcap pcap = Pcap.openLive("eth0", snaplen, 1, 10 * oneSecond, errbuf);
		assertNotNull(errbuf.toString(), pcap);

		byte[] a = new byte[14];
		Arrays.fill(a, (byte) 0xff);

		ByteBuffer b = ByteBuffer.wrap(a);

		if (pcap.inject(b) < 0) {
			fail(pcap.getErr());
		}

		pcap.close();

	}

}
