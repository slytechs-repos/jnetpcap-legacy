/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.newstuff.analysis.statistics;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.TestUtils;



/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class StatisticsExample {

	/**
	 * @param args
	 */
	public static void main(String[] args) {



		final StatisticAnalyzer stats = new StatisticAnalyzer();
		final String[] labels = stats.labels();
		
		TestUtils.displayInFrame(new SwingStatisticsPanel(stats));

		final Thread thread = new Thread(new Runnable() {

			public void run() {
				while (true) {
					try {
						Thread.sleep(5000);
					} catch (InterruptedException e) {
						e.printStackTrace();
					} // 1 second

					long[] counters = stats.snapshot();
					System.out.printf("(%3d) ", stats.total());
					for (int i = 0; i < 20; i++) {
						if (counters[i] != 0L) {
							System.out.printf("%3s(%3d) ", labels[i], counters[i]);
						}
					}

					System.out.printf("\r");
					System.out.flush();
					
					
				}
			}

		});

		thread.start();

		TestUtils.openLive(new JPacketHandler<Pcap>() {

			public void nextPacket(JPacket packet, Pcap user) {
				stats.processPacket(packet);
			}

		});

	}

}
