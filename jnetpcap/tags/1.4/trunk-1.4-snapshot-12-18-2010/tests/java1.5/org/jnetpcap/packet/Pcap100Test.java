/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.compatibility.Pcap100;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Pcap100Test
    extends
    TestCase {

	public void testInVer1_3() {
		StringBuilder errbuf = new StringBuilder();
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		int snaplen = 64 * 1024;
		int promisc = Pcap.MODE_PROMISCUOUS;
		int timeout = Pcap.DEFAULT_TIMEOUT;
		int bufsize = 128 * 1024 * 1024;
		int direction = Pcap100.INOUT;

		if (Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK) {
			fail(errbuf.toString());
		}
		String device = alldevs.get(0).getName();

		Pcap pcap = null;
		if (Pcap100.IS_IMPLEMENTED) {
			Pcap100 pcap100 = Pcap100.create(device, errbuf);
			assertNotNull(errbuf.toString(), pcap100);

			pcap100.setSnaplen(snaplen);
			pcap100.setTimeout(timeout);
			pcap100.setPromisc(promisc);
			pcap100.setBufferSize(bufsize);
			pcap100.setDirection(direction);

			pcap100.activate();

			pcap = pcap100;
		} else {
			pcap = Pcap.openLive(device, snaplen, promisc, timeout, errbuf);
			assertNotNull(errbuf.toString(), pcap);
		}

		if (pcap != null) {
			pcap.close();
		}
	}

public void testInVer1_4() {
	StringBuilder errbuf = new StringBuilder();
	List<PcapIf> alldevs = new ArrayList<PcapIf>();
	int snaplen = 64 * 1024;
	int promisc = Pcap.MODE_PROMISCUOUS;
	int timeout = Pcap.DEFAULT_TIMEOUT;
	int bufsize = 128 * 1024 * 1024;
	int direction = Pcap.INOUT;

	if (Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK) {
		fail(errbuf.toString());
	}
	String device = alldevs.get(0).getName();

	Pcap pcap = null;
	pcap = Pcap.create(device, errbuf);
	assertNotNull(errbuf.toString(), pcap);

	pcap.setSnaplen(snaplen);
	pcap.setTimeout(timeout);
	pcap.setPromisc(promisc);
	pcap.setBufferSize(bufsize);
	pcap.setDirection(direction);

	pcap.activate();

	pcap.close();
}

public void testInVer1_4WithCheck() {
	StringBuilder errbuf = new StringBuilder();
	List<PcapIf> alldevs = new ArrayList<PcapIf>();
	int snaplen = 64 * 1024;
	int promisc = Pcap.MODE_PROMISCUOUS;
	int timeout = Pcap.DEFAULT_TIMEOUT;
	int bufsize = 128 * 1024 * 1024;
	int direction = Pcap.INOUT;

	if (Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK) {
		fail(errbuf.toString());
	}
	String device = alldevs.get(0).getName();

	Pcap pcap = null;
	if (Pcap.isPcap100Supported()) {
		pcap = Pcap.create(device, errbuf);
		assertNotNull(errbuf.toString(), pcap);

		pcap.setSnaplen(snaplen);
		pcap.setTimeout(timeout);
		pcap.setPromisc(promisc);
		pcap.setBufferSize(bufsize);
		pcap.setDirection(direction);

		pcap.activate();
	} else {
		pcap = Pcap.openLive(device, snaplen, promisc, timeout, errbuf);
		assertNotNull(errbuf.toString(), pcap);
	}

	pcap.close();
}
}
