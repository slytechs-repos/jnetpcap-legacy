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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Exchanger;

import junit.framework.TestCase;

import org.jnetpcap.winpcap.WinPcap;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("deprecation")
public class TestOpenCloseMultiThreaded
    extends TestCase {

	private boolean looping = false;

	private final PcapHandler<Pcap> callback = new PcapHandler<Pcap>() {

		public void nextPacket(Pcap pcap, long seconds, int useconds, int caplen,
		    int len, ByteBuffer buffer) {

			if (looping == false) {
				try {
					exchanger.exchange(pcap);
				} catch (InterruptedException e) {
					System.out
					    .println("Exchange of pcap between threads failed in child thread");
					System.exit(1);
				}
				looping = true;
			}
		}
	};

	private final Exchanger<Pcap> exchanger = new Exchanger<Pcap>();

	private Pcap openAndLoop() {

		looping = false;
		final List<PcapIf> alldevs = new ArrayList<PcapIf>();
		final StringBuilder errbuf = new StringBuilder();
		Pcap.findAllDevs(alldevs, errbuf);

		// System.out.println(alldevs);

		final WinPcap pcap =
		    WinPcap.openLive(alldevs.get(0).getName(), 65 * 1024, 1, 0, errbuf);
		pcap.setMinToCopy(0);

		pcap.loop(0, callback, pcap);

		return pcap;
	}

	public void test1() throws InterruptedException {

		final int COUNT = 30;

		for (int i = 0; i < COUNT; i++) {
			// System.out.println("Loop #" + i);

			final Thread t = new Thread(new Runnable() {

				public void run() {
					openAndLoop();
				}

			});

			t.start();

			final Pcap pcap = exchanger.exchange(null);
			pcap.breakloop();
			t.join();
			pcap.close();

		}

	}

}
