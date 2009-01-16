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
package org.jnetpcap.analysis;

import java.util.Comparator;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.util.JPacketSupport;
import org.jnetpcap.util.TimeoutQueue;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unchecked")
public class JController
    extends AbstractAnalyzer implements JPacketHandler<Pcap> {

	private final static int INITIAL_CAPACITY = 1000;

	private JPacketSupport support = new JPacketSupport();

	private Comparator<JAnalyzer> ANALYZER_PRIORITY =
	    new Comparator<JAnalyzer>() {

		    public int compare(JAnalyzer o1, JAnalyzer o2) {
			    return o1.getPriority() - o2.getPriority();
		    }

	    };

	private Comparator<JPacket> PACKET_TIMESTAMP = new Comparator<JPacket>() {

		public int compare(JPacket o1, JPacket o2) {
			return (int) (o1.getCaptureHeader().timestampInMillis() - o2
			    .getCaptureHeader().timestampInMillis());
		}

	};

	private TimeoutQueue timeouts = new TimeoutQueue();

	private Queue<JPacket> inQ =
	    new PriorityQueue<JPacket>(INITIAL_CAPACITY, PACKET_TIMESTAMP);

	private Queue<JPacket> outQ =
	    new PriorityQueue<JPacket>(INITIAL_CAPACITY, PACKET_TIMESTAMP);

	private Set<JAnalyzer>[] analyzers = new TreeSet[JRegistry.MAX_ID_COUNT];

	private long analyzerMap = 0;

	public void addAnalyzer(JAnalyzer analyzer, int id) {
		analyzerMap |= (1L << id);

		getAnalyzers(id).add(analyzer);
		analyzer.setParent(this);
	}

	public Set<JAnalyzer> getAnalyzers(int id) {
		if (analyzers[id] == null) {
			analyzers[id] = new TreeSet<JAnalyzer>(ANALYZER_PRIORITY);
		}

		return analyzers[id];
	}

	public <T> boolean add(JPacketHandler<T> o, T user) {
		return this.support.add(o, user);
	}

	public boolean remove(JPacketHandler<?> o) {
		return this.support.remove(o);
	}

	protected void processQueue() {

		while (inQ.isEmpty() == false) {
			JPacket p = inQ.poll();

			super.setProcessingTime(p);
			processPacket(p);

			outQ.offer(p);
		}
	}

	protected void processingComplete() {

		while (outQ.isEmpty() == false) {
			support.fireNextPacket(outQ.poll());
		}

	}

	public void nextPacket(JPacket packet, Pcap pcap) {

		/*
		 * Set the curren time from the packet stream
		 */
		super.setProcessingTime(packet);

		/*
		 * Process the timeout queue and timeout any entries based on the latest
		 * time
		 */
		timeouts.timeout(getProcessingTime());

		/*
		 * Put the packet on the inbound queue to be processed
		 */
		inQ.offer(packet); // inQ is sorted by capture timestamp

		/*
		 * Process the inbound queue of packets
		 */
		processQueue();

		/**
		 * Process the outbound queue of packets
		 */
		processingComplete();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AbstractAnalyzer#processPacket(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) {
		long map = packet.getState().get64BitHeaderMap(0);
		if ((map & analyzerMap) == 0) {
			return true; // No analyzers matching headers in the packet
		}

		int count = packet.getHeaderCount();
		map &= analyzerMap; // Just leave the analyzers from the map
		for (int i = 0; i < count && map != 0; i++) {
			int id = packet.getHeaderIdByIndex(i);
			if ((map & (1L << id)) == 0) {
				continue;
			}

			/*
			 * Turn off the analyzer ID bit we just processed. This allows us to check
			 * entire map and end loop quickly if no more analyzers are present for
			 * current header map
			 */
			map &= ~(1L << id);

			/*
			 * Now go through all the analyzers for this protocol, sorted by priority
			 */
			for (JAnalyzer analyzer : analyzers[id]) {
				analyzer.processPacket(packet);
			}
		}

		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalyzer#getPriority()
	 */
	public int getPriority() {
		return 0; // Highest priority
	}
}
