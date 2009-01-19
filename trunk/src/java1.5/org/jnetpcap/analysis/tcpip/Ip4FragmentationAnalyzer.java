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

import java.util.Formatter;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import org.jnetpcap.analysis.AbstractAnalyzer;
import org.jnetpcap.analysis.AnalysisInfo;
import org.jnetpcap.analysis.AnalyzerListener;
import org.jnetpcap.analysis.AnalyzerSupport;
import org.jnetpcap.analysis.FragmentReassembly;
import org.jnetpcap.analysis.FragmentSequence;
import org.jnetpcap.analysis.FragmentSequenceAnalyzer;
import org.jnetpcap.analysis.FragmentSequenceEvent;
import org.jnetpcap.analysis.JAnalysis;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.util.JLogger;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Ip4FragmentationAnalyzer
    extends AbstractAnalyzer implements FragmentSequenceAnalyzer {

	private final static Logger logger =
	    JLogger.getLogger(Ip4FragmentationAnalyzer.class);

	/**
	 * The default timeout interval in millis for a fragment sequence completion.
	 */
	public final static int DEFAULT_FRAGMENT_TIMEOUT = 60 * 1000; // 60 seconds

	private static final int SIZE = 500;

	private final Map<Integer, FragmentSequence> fragmentation =
	    new HashMap<Integer, FragmentSequence>(SIZE);

	private final AnalyzerSupport<FragmentSequenceEvent> fragSupport =
	    new AnalyzerSupport<FragmentSequenceEvent>();

	private final Ip4 ip = new Ip4();

	private final List<JAnalysis> list = new LinkedList<JAnalysis>();

	private final Formatter out =
	    new Formatter(outStringBuilder = new StringBuilder());

	private final StringBuilder outStringBuilder;

	private long timeout = DEFAULT_FRAGMENT_TIMEOUT;

	public boolean addFragmentationListener(
	    AnalyzerListener<FragmentSequenceEvent> listener) {
		return this.fragSupport.addListener(listener, null);
	}

	FragmentReassembly reassembly = new FragmentReassembly();

	public List<JAnalysis> generateInfo(FragmentSequence sequence) {
		list.clear();

		if (sequence.hasAllFragments()) {
			list.add(new AnalysisInfo("Status", "all fragments found"));
		} else {
			list.add(new AnalysisInfo("Status", "fragments still missing with "
			    + (sequence.getTimeout() - getProcessingTime()) + " ms remaining"));
		}

		long last = 0;
		for (JPacket packet : sequence.getPacketSequence()) {
			if (packet.hasHeader(ip)) {
				int start = ip.offset() * 8;
				int end = start + ip.length() - ip.hlen() * 4 - 1;
				long delta =
				    (last == 0) ? 0 : packet.getCaptureHeader().timestampInNanos()
				        - last;
				last = packet.getCaptureHeader().timestampInNanos();
				long frame = packet.getState().getFrameNumber();

				Set<Ip4.Flag> flags = ip.flagsEnum();

				outStringBuilder.setLength(0);
				out.format("offset=%4d-%4d, len=%3d, dts=%.2f us, flags=%s", start,
				    end, ip.length(), (delta < 0) ? 0 : ((float) delta / 1000.0), flags
				        .toString());

				list.add(new AnalysisInfo("Frame #" + frame, out.toString()));
			}
		}

		return list;
	}

	private FragmentSequence getSequence(int hash) {
		/*
		 * Sorted by ip offset
		 */
		FragmentSequence sequence = fragmentation.get(hash);
		if (sequence == null) {
			sequence = new FragmentSequence(hash, this);
			sequence.setTimeout(getProcessingTime() + timeout);

			fragmentation.put(hash, sequence);
			getTimeoutQueue().add(sequence);
		}

		return sequence;

	}

	private boolean processFragmentation(JPacket packet) {
		int hash = ip.hashCode(); // Unidirectional Ip.source/Ip.destination
		int offset = ip.offset() * 8;
		int length = ip.length() - ip.hlen() * 4;

		if (ip.flags_MF() == 0 && offset == 0) {
			return true; // IP datagram not fragmented
		}

		FragmentSequence sequence = getSequence(hash);

		if (sequence.isEmpty()) {
			fragSupport.fire(FragmentSequenceEvent.sequenceStart(this, sequence));
		}

		fragSupport.fire(FragmentSequenceEvent.sequenceNewPacket(this, sequence,
		    packet));
		sequence.addFragment(packet, offset, length);

		if (ip.offset() == 0) {
			sequence.setHasFirstFragment(true);
		}

		if (ip.flags_MF() == 0 && offset != 0) {
			sequence.setHasLastFragment(true);
			sequence.setTotalLength(offset + length);
		}

		ip.addAnalysis(sequence);

		// System.out.printf("offset=%d len=%d, total=%d\n", offset,
		// sequence.getLen(), sequence.getTotalLength());

		if (sequence.hasLastFragment()
		    && sequence.getLen() == sequence.getTotalLength()) {
			sequence.setHasAllFragments(true);

			getTimeoutQueue().timeout(sequence);
//			System.out.printf("Completed id=%x seg=%d %s->%s fragQueue=%d\n",
//			    ip.id(), sequence.getPacketSequence().size(), FormatUtils.ip(ip
//			        .source()), FormatUtils.ip(ip.destination()), this.fragmentation
//			        .size());

			fragSupport.fire(FragmentSequenceEvent.sequenceComplete(this, sequence));
		}

		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AbstractAnalyzer#process(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) {
		if (packet.hasHeader(ip)) {
			return processFragmentation(packet);
		}

		return true;
	}

	public boolean removeFragmentationListener(
	    AnalyzerListener<FragmentSequenceEvent> listener) {
		return this.fragSupport.removeListener(listener);
	}

	protected void setProcessingTime(JPacket packet) {
		packet.getCaptureHeader().timestampInMillis();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalyzer#timeout(org.jnetpcap.analysis.JAnalysis)
	 */
	public void timeout(FragmentSequence analysis) {
		if (fragmentation.remove(analysis.hashCode()) == null) {
			logger.warning("Unable to remove analysis info from fragmentation map");
		}

		fragSupport.fire(FragmentSequenceEvent.sequenceTimeout(this, analysis));
	}

}
