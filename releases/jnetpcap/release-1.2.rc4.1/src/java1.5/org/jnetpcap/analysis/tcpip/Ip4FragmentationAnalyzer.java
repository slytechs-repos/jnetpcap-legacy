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

import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.analysis.AnalyzerListener;
import org.jnetpcap.analysis.AnalyzerSupport;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.header.Ip4;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Ip4FragmentationAnalyzer implements FragmentSequenceAnalyzer {

	private static final int SIZE = 500;

	private Map<Integer, FragmentSequence> fragmentation =
	    new HashMap<Integer, FragmentSequence>(SIZE);

	private AnalyzerSupport<FragmentSequenceEvent> fragSup =
	    new AnalyzerSupport<FragmentSequenceEvent>();

	private final Ip4Analyzer parent;

	public Ip4FragmentationAnalyzer(Ip4Analyzer parent) {
		this.parent = parent;
	}

	public boolean addFragmentationListener(
	    AnalyzerListener<FragmentSequenceEvent> listener) {
		return this.fragSup.addListener(listener, null);
	}

	private FragmentSequence getSequence(int hash) {
		/*
		 * Sorted by ip offset
		 */
		FragmentSequence sequence = fragmentation.get(hash);
		if (sequence == null) {
			sequence = new FragmentSequence();

			fragmentation.put(hash, sequence);
		}

		return sequence;

	}

	public void process(JPacket packet, Ip4 ip) {
		processFragmentation(packet, ip);
	}

	private void processFragmentation(JPacket packet, Ip4 ip) {
		int hash = ip.hashCode(); // Unidirectional Ip.source/Ip.destination
		int offset = ip.offset() * 8;
		int length = ip.length();

		if (ip.flags_DF() == 1 || ip.flags_MF() == 0 && offset == 0) {
			return; // IP datagram not fragmented
		}

		FragmentSequence sequence = getSequence(hash);

		if (sequence.isEmpty()) {
			fragSup.fire(FragmentSequenceEvent.sequenceStart(this, sequence));
		}

		fragSup.fire(FragmentSequenceEvent
		    .sequenceNewPacket(this, sequence, packet));
		sequence.addFragment(packet, offset, length);

		packet.addAnalysis(sequence);
	}

	public boolean removeFragmentationListener(
	    AnalyzerListener<FragmentSequenceEvent> listener) {
		return this.fragSup.removeListener(listener);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalyzer#timeout(org.jnetpcap.analysis.JAnalysis)
	 */
	public void timeout(FragmentSequence analysis) {
		fragmentation.remove(analysis);

		fragSup.fire(FragmentSequenceEvent.sequenceTimeout(this, analysis));
	}
}
