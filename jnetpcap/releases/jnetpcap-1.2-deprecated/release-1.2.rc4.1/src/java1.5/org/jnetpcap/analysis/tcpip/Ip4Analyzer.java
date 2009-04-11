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
package org.jnetpcap.analysis.tcpip;

import java.util.Iterator;
import java.util.PriorityQueue;
import java.util.Queue;

import org.jnetpcap.analysis.JAnalyzer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.util.Timeout;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Ip4Analyzer implements JAnalyzer, PcapPacketHandler<Object> {

	private final Ip4 ip = new Ip4();

	/*
	 * This is our processing time, not the system time. This time is set from the
	 * capture timestamp of the last packet. If packet was read from a file, its
	 * the saved timestamp. Of if this is a live capture it may be the system
	 * timestamp.
	 */
	private long timeInMillis = 0;

	/**
	 * This queue contains various analysis objects that are time constrained.
	 * Such as IP fragmentation. If all the fragments don't arrive within a
	 * reassembly time window, then we timeout that analysis object, remove it
	 * from maps and notify any listeners that analysis expired. The time is taken
	 * from all arriving packets as they are read. Their timestamp determines the
	 * current processing time (which is different from current system clock as we
	 * might be reading from a file using saved timestamps.
	 */
	private Queue<Timeout> timeoutQueue = new PriorityQueue<Timeout>();

	private Ip4FragmentationAnalyzer fragmentation =
	    new Ip4FragmentationAnalyzer(this);

	/**
	 * Main entry point for the analyzer. This is where all the packets arrive and
	 * where they are processed.
	 * 
	 * @see org.jnetpcap.packet.PcapPacketHandler#nextPacket(org.jnetpcap.packet.PcapPacket,
	 *      java.lang.Object)
	 */
	public void nextPacket(PcapPacket packet, Object user) {

		setProcessingTime(packet); // Set processing time
		timeout(); // Process timeout queue

		/*
		 * We're only interested in Ip4 packets
		 */
		if (packet.hasHeader(ip)) {
			/*
			 * Keep track of IP fragments. Assign FragmentSequence analysis object to
			 * each packet part of a fragment group.
			 */
			fragmentation.process(packet, ip);
		}
	}

	private void setProcessingTime(org.jnetpcap.packet.JPacket packet) {
		this.timeInMillis = packet.getCaptureHeader().timestampInMillis();
	}

	/**
	 * 
	 */
	private void timeout() {

		for (Iterator<Timeout> i = timeoutQueue.iterator(); i.hasNext();) {
			Timeout analysis = i.next();
			if (analysis.isTimedout(timeInMillis)) {
				i.remove();
				analysis.timeout();

			} else {
				break;
			}
		}
	}

	/**
	 * @return
	 */
	public long getTimeInMillis() {
		return this.timeInMillis;
	}
}
