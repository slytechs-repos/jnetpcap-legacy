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
package org.jnetpcap.protocol.tcpip;

import java.util.ArrayList;
import java.util.Formatter;
import java.util.List;

import org.jnetpcap.analysis.AbstractSequencer;
import org.jnetpcap.analysis.AnalysisInfo;
import org.jnetpcap.analysis.AnalyzerListener;
import org.jnetpcap.analysis.FragmentSequence;
import org.jnetpcap.analysis.FragmentSequenceEvent;
import org.jnetpcap.analysis.JAnalysis;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.util.JThreadLocal;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpSequencer
    extends AbstractSequencer implements
    AnalyzerListener<TcpStreamEvent> {

	private final TcpAnalyzer analyzer;

	private JThreadLocal<Ip4> ipLocal = new JThreadLocal<Ip4>(Ip4.class);

	private JThreadLocal<Tcp> tcpLocal = new JThreadLocal<Tcp>(Tcp.class);

	public TcpSequencer() {
		super(200, JRegistry.getAnalyzer(TcpAnalyzer.class));

		this.analyzer = JRegistry.getAnalyzer(TcpAnalyzer.class);

		this.analyzer.addTcpStreamListener(this, null);

	}

	private final Formatter out =
	    new Formatter(outStringBuilder = new StringBuilder());

	private final StringBuilder outStringBuilder;

	private boolean consume;

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.FragmentSequencer#generateInfo(org.jnetpcap.analysis.FragmentSequence)
	 */
	public List<JAnalysis> generateInfo(FragmentSequence sequence) {
		List<JAnalysis> list = new ArrayList<JAnalysis>();
		list.clear();
		Tcp tcp = tcpLocal.get();

		if (sequence.hasAllFragments()) {
			list.add(new AnalysisInfo("Status", "all fragments found"));
		} else {
			list.add(new AnalysisInfo("Status", "fragments still missing with "
			    + (sequence.getTimeout() - getProcessingTime()) + " ms remaining"));
		}

		long last = 0;
		for (JPacket packet : sequence.getPacketSequence()) {
			if (packet.hasHeader(tcp)) {
				long start = tcp.seq() - sequence.getStart();
				long end = start + tcp.getPayloadLength();
				long delta =
				    (last == 0) ? 0 : packet.getCaptureHeader().timestampInNanos()
				        - last;
				last = packet.getCaptureHeader().timestampInNanos();
				long frame = packet.getState().getFrameNumber();

				outStringBuilder.setLength(0);
				out.format("offset=%4d-%4d, len=%3d, dts=%.2f us, flags=%s", start,
				    end, tcp.getPayloadLength(), (delta < 0) ? 0
				        : ((float) delta / 1000.0), tcp.flagsEnum());

				list.add(new AnalysisInfo("Frame #" + frame, out.toString()));
			}
		}

		return list;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AnalyzerListener#processAnalyzerEvent(org.jnetpcap.analysis.AnalyzerEvent)
	 */
	public void processAnalyzerEvent(TcpStreamEvent evt) {
		
		if (evt.getType() == TcpStreamEvent.Type.ACKED_SEGMENT) {
			final JPacket packet = evt.getPacket();
			final TcpStream stream = evt.getStream();
			int hash = stream.hashCode();
			Tcp tcp = tcpLocal.get();
			Ip4 ip = ipLocal.get();
			setProcessingTime(packet);

			if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
				FragmentSequence sequence = getSequence(hash, false);
				if (sequence == null) {
					return;
				}

				int length = tcp.getPayloadLength();
				long seq = tcp.seq();
				long start = sequence.getStart();
				long end = start + sequence.getTotalLength();

				if (seq < sequence.getStart() || seq >= end) {
					return;
				}

				if (sequence.isEmpty()) {
					sequence.setHasFirstFragment(true);
				} else if (consume) {
					/*
					 * if consume flag is set, we consume, not return to the user except
					 * for the first fragment. The packets are still there but they are
					 * now only accessible by getting the FragmentationSequence from that
					 * first segment we did not consume. The flag is toggled using
					 * setConsume(boolean) method.
					 */
					super.consumePacket(packet);
				}

				sequence.addFragment(packet, (int) tcp.seq(), length);
				// tcp.addAnalysis(sequence);

//				long nseq = seq - start;
//				long delta = sequence.getTotalLength() - nseq - length;
				// System.out.printf("#%d seq=%d-%d::%5d seg.len=%d rcv.len=%d :: ",
				// packet.getFrameNumber(), nseq, nseq + length, delta, length,
				// sequence.getLen());

				fragSupport.fire(FragmentSequenceEvent.sequenceNewPacket(this,
				    sequence, packet));

				if (sequence.getLen() == sequence.getTotalLength()) {
					sequence.setHasLastFragment(true);
					sequence.setHasAllFragments(true);
					getTimeoutQueue().timeout(sequence);
					super.removeSequence(hash);
					
					fragSupport.fire(FragmentSequenceEvent.sequenceComplete(this,
					    sequence));

					// System.out.printf("#%d %s\n", tcp.toString());
				}
			}
		}
	}


	public boolean processPacket(JPacket packet) {

		return true;
	}

	public void setFragmentationBoundary(int hash, long start, long length) {

		FragmentSequence sequence = getSequence(hash, true);
		sequence.setTotalLength((int) length);
		sequence.setStart(start);

//		System.out.printf("map=%s\n", fragmentation.keySet());
	}

	public void setFragmentationBoundary(JPacket packet, long length) {
		Tcp tcp = tcpLocal.get();
		Ip4 ip = ipLocal.get();
		setProcessingTime(packet);

		if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
			setFragmentationBoundary(tcp.hashCode(), tcp.seq(), length);
		}
	}

	/**
	 * @param b
	 */
	public void setConsume(boolean consume) {
		this.consume = consume;
	}

}
