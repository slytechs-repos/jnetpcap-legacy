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
package org.jnetpcap.bugs;

import java.io.File;
import java.io.FilenameFilter;

import junit.framework.TestCase;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * 1.3.b0006 coredumps on the following platforms: ubuntu, fedora and debian.
 * 
 * <pre>
 * Stack: [0x9f13b000,0x9f18c000], sp=0x9f18abfc, free space=318k
 * Native frames: (J=compiled Java code, j=interpreted, Vv=VM code, C=native
 * code)
 * C [libc.so.6+0x7b3d1] memcpy+0x61
 * 
 * [error occurred during error reporting (printing native stack), id 0xb]
 * 
 * Java frames: (J=compiled Java code, j=interpreted, Vv=VM code)
 * J
 * org.jnetpcap.Pcap.dispatch(IILorg/jnetpcap/packet/JPacketHandler;Ljava/lang
 * /Object;Lorg/jnetpcap/packet/JPacket;Lorg/jnetpcap/packet/JPacket$State;Lor
 * g/jnetpcap/PcapHeader;Lorg/jnetpcap/packet/JScanner;)I
 * J
 * org.jnetpcap.Pcap.dispatch(ILorg/jnetpcap/packet/JPacketHandler;Ljava/lang/
 * Object;Lorg/jnetpcap/packet/JScanner;)I
 * J
 * com.abcompany.XXX.XXX.XXX.executeDispatch(Ljava/util/concurrent/BlockingQue
 * ue;)Z
 * J com.abcompany.CCC.CCC.CCC$3.run()V
 * j java.lang.Thread.run()V+11
 * v &tilde;StubRoutines::call_stub
 * </pre>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Bug2836179_coredump_all_platforms
    extends
    TestCase {

	private final static File DIR = new File("tests");

	private static final int COUNT = 1;

	private StringBuilder errbuf;

	@Override
	protected void setUp() throws Exception {
		errbuf = new StringBuilder();
	}

	@Override
	protected void tearDown() throws Exception {
		errbuf = null;
	}

	public void testStressTestJPacketHandler() {
		String[] files = DIR.list(new FilenameFilter() {

			public boolean accept(File dir, String name) {
				return name.endsWith(".pcap");
			}

		});

		for (int i = 0; i < COUNT; i++) {
			for (final String fname : files) {
				Pcap pcap = Pcap.openOffline(DIR.toString() + "/" + fname, errbuf);
				assertNotNull(errbuf.toString(), pcap);

				pcap.loop(Pcap.LOOP_INFINATE, new JPacketHandler<Pcap>() {

					public void nextPacket(JPacket packet, Pcap user) {
						assertNotNull(packet);

						System.out.printf("%s#%d headerCount=%d\r", fname, packet
						    .getFrameNumber(), packet.getState().getHeaderCount());

					}

				}, pcap);

				pcap.close();
			}

			System.out.printf(".");
			System.out.flush();
		}

		System.out.println();
	}

	public void testStressTestPcapPacketHandler() {
		String[] files = DIR.list(new FilenameFilter() {

			public boolean accept(File dir, String name) {
				return name.endsWith(".pcap");
			}

		});

		for (int i = 0; i < COUNT; i++) {
			for (String fname : files) {
				Pcap pcap = Pcap.openOffline(DIR.toString() + "/" + fname, errbuf);
				assertNotNull(errbuf.toString(), pcap);

				pcap.loop(Pcap.LOOP_INFINATE, new PcapPacketHandler<Pcap>() {

					public void nextPacket(PcapPacket packet, Pcap user) {
						assertNotNull(packet);

					}

				}, pcap);

				pcap.close();
			}

			System.out.printf(".");
			System.out.flush();
		}

		System.out.println();
	}

}
