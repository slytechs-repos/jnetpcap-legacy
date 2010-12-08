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
package org.jnetpcap.winpcap;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 * All the examples that have been documented within WinPcap extension, go here
 * to verify syntax and functionality. This jUnit class makes sure that all the
 * examples listed are valid and properly working. The examples sometimes may
 * strip out try/catch, import and method declaration statements, but in reality
 * they are based on fully working examples, which we test here.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestWinPcapCommentExamples
    extends TestCase {

	String source = "rpcap://\\Device\\NPF_{BC81C4FC-242F-4F1C-9DAD-EA9523CC992D}";

	int snaplen = 64 * 1024;

	int flags = Pcap.MODE_NON_PROMISCUOUS;

	int timeout = 1000;

	WinPcapRmtAuth auth = null;

	StringBuilder errbuf = new StringBuilder();

	/**
	 * @throws java.lang.Exception
	 */
	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	public void tearDown() throws Exception {
	}

	public void testWinPcapMainCommentEx1() {
		assertTrue("WinPcap extension not supported on this platform", WinPcap
		    .isSupported());

		WinPcap pcap = WinPcap.open(source, snaplen, flags, timeout, auth, errbuf);
		assertNotNull(pcap);
		pcap.close();
	}

	public void testWinPcapMainCommentEx2() {
		String source = "rpcap://\\Device\\PF_{BC81C4FC-242F-4F1C-9DAD-EA9523CC992D}";
		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_NON_PROMISCUOUS;
		int timeout = 1000;
		WinPcapRmtAuth auth = null;
		StringBuilder errbuf = new StringBuilder();

		WinPcap pcap = WinPcap.open(source, snaplen, flags, timeout, auth, errbuf);
		if (pcap == null) {
			fail(errbuf.toString());
			return;
		}
		pcap.close();
	}

	public void testWinPcapMainCommentFindAllDevsEx() {
		String source = "rpcap://";
		List<PcapIf> alldevs = new ArrayList<PcapIf>();

		int r = WinPcap.findAllDevsEx(source, auth, alldevs, errbuf);
		if (r != Pcap.OK) {
			fail(errbuf.toString());
			return;
		}

		System.out.println("device list is " + alldevs);

	}

	public void testWinPcapMainCommentCreateStr() {
		String source = "rpcap://";
		List<PcapIf> alldevs = new ArrayList<PcapIf>();

		int r = WinPcap.findAllDevsEx(source, auth, alldevs, errbuf);
		if (r != Pcap.OK) {
			fail(errbuf.toString());
			return;
		}

		StringBuilder buf = new StringBuilder();
		WinPcap.createSrcStr(buf, WinPcap.SRC_IFLOCAL, null, null, alldevs.get(0)
		    .getName(), errbuf);

		System.out.println("Our source string is " + alldevs.get(0).getName());
	}
}
