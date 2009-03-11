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
package org.jnetpcap.protocol.network;

import java.util.Formatter;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.analysis.AbstractSequencer;
import org.jnetpcap.packet.analysis.AnalysisInfo;
import org.jnetpcap.packet.analysis.FragmentSequence;
import org.jnetpcap.packet.analysis.FragmentSequenceEvent;
import org.jnetpcap.packet.analysis.FragmentSequencer;
import org.jnetpcap.packet.analysis.JAnalysis;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Ip4Sequencer
    extends AbstractSequencer implements FragmentSequencer {

	private final Ip4 ip = new Ip4();

	private final List<JAnalysis> list = new LinkedList<JAnalysis>();

	private final Formatter out =
	    new Formatter(outStringBuilder = new StringBuilder());

	private final StringBuilder outStringBuilder;

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

	private boolean processFragmentation(JPacket packet) {
		int hash = ip.hashCode(); // Unidirectional Ip.source/Ip.destination
		int offset = ip.offset() * 8;
		int length = ip.length() - ip.hlen() * 4;

		if (ip.flags_MF() == 0 && offset == 0) {
			return true; // IP datagram not fragmented
		}

		FragmentSequence sequence = getSequence(hash, true);

		sequence.addFragment(packet, offset, length);
		fragSupport.fire(FragmentSequenceEvent.sequenceNewPacket(this, sequence,
		    packet));

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
	 * @see org.jnetpcap.packet.analysis.AbstractAnalyzer#process(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) {
		if (packet.hasHeader(ip)) {
			return processFragmentation(packet);
		}

		return true;
	}

}
