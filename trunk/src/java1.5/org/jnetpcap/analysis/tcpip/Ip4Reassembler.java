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

import java.util.List;
import java.util.Queue;
import java.util.logging.Logger;

import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.analysis.AbstractAnalyzer;
import org.jnetpcap.analysis.AnalysisInfo;
import org.jnetpcap.analysis.AnalyzerListener;
import org.jnetpcap.analysis.AnalyzerSupport;
import org.jnetpcap.analysis.FragmentReassembly;
import org.jnetpcap.analysis.FragmentReassemblyAnalyzer;
import org.jnetpcap.analysis.FragmentReassemblyEvent;
import org.jnetpcap.analysis.FragmentSequence;
import org.jnetpcap.analysis.FragmentSequenceEvent;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JMemoryPool;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.util.JLogger;
import org.jnetpcap.util.JThreadLocal;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Ip4Reassembler
    extends AbstractAnalyzer implements FragmentReassemblyAnalyzer,
    AnalyzerListener<FragmentSequenceEvent> {

	private static final int IP4_HEADER_LENGTH = 20;

	private AnalyzerSupport<FragmentReassemblyEvent> support =
	    new AnalyzerSupport<FragmentReassemblyEvent>();

	/**
	 * First thread local pool of ips
	 */
	private final static ThreadLocal<Ip4> ipLocal1 =
	    new JThreadLocal<Ip4>(Ip4.class);

	/**
	 * Second thread local pool if ips
	 */
	private final static ThreadLocal<Ip4> ipLocal2 =
	    new JThreadLocal<Ip4>(Ip4.class);

	private final static Logger logger = JLogger.getLogger(Ip4Reassembler.class);

	private final static JMemoryPool memory = new JMemoryPool();

	private static final int PRIORITY = 200;

	private FragmentReassembly reassembly = new FragmentReassembly();

	private static Ip4 createIp4HeaderFromSequence(
	    JBuffer buf,
	    FragmentSequence seq) {
		Ip4 ip = ipLocal1.get();
		JPacket front = seq.getPacketSequence().get(0);
		front.getHeader(ip);

		/*
		 * Copy Ip4 header from the first fragment
		 */
		ip.transferTo(buf);

		/*
		 * Peer ip header with front of the buffer so we can adjust certain settings
		 * in the header.
		 */
		ip.peer(buf, 0, IP4_HEADER_LENGTH);

		return ip;
	}

	public static JPacket createPacketFromSequence(FragmentSequence seq) {
		int totalLength = seq.getTotalLength();

		/*
		 * Create a buffer and allocate memory more efficiently
		 */
		JBuffer buf = new JBuffer(JMemory.Type.POINTER);
		memory.allocate(totalLength + IP4_HEADER_LENGTH, buf);

		Ip4 header = createIp4HeaderFromSequence(buf, seq);
		List<JPacket> list = seq.getPacketSequence();

		Ip4 ip = ipLocal2.get();
		for (JPacket packet : list) {
			if (packet.hasHeader(ip)) {
				int length = ip.length() - ip.hlen() * 4;
				int offset = ip.offset() * 8;
				int ipPayloadOffset = ip.getOffset() + ip.hlen() * 4;

				packet.transferTo(buf, ipPayloadOffset, length, offset
				    + IP4_HEADER_LENGTH);

			} else {
				logger
				    .warning("Fragment sequence contains non-IP packet in packet frame #"
				        + packet.getState().getFrameNumber());
				return null;
			}
		}

		JPacket back = list.get(list.size() - 1);

		/*
		 * Adjust header fields to reflect new packet
		 */
		header.hlen(IP4_HEADER_LENGTH / 4);
		header.offset(0);
		header.length(totalLength + IP4_HEADER_LENGTH);
		header.flags(header.flags() & ~Ip4.FLAG_MORE_FRAGMENTS);
		header.checksum(0); // TODO: need to calculate Ip4 header CRC

		/*
		 * Create the new packet and return it
		 */
		JPacket packet = new JMemoryPacket(Ip4.ID, buf);
		packet.getHeader(header); // Repeer to new packet
		header.addAnalysis(new FragmentReassembly(packet, seq));


		JCaptureHeader capture = packet.getCaptureHeader();
		capture.initFrom(back.getCaptureHeader());
		capture.nanos(back.getCaptureHeader().nanos() + 1); // We need a later TS

		/*
		 * Lastly tag each packet within the reassembled sequence with info about
		 * where the reassembled PDU is
		 */
		for (JPacket p : seq.getPacketSequence()) {
			if (p.hasHeader(ip)) {
				ip.addAnalysis(new AnalysisInfo("Reassembled PDU",
				    "reassembled PDU in frame #" + (back.getFrameNumber() + 1)));
			}
		}


		return packet;
	}

	/**
	 * @param priority
	 */
	public Ip4Reassembler() {
		super(PRIORITY);
	}

	/**
	 * @param priority
	 * @param parent
	 */
	public Ip4Reassembler(AbstractFragmentationAnalyzer parent) {
		super(PRIORITY, parent);

		parent.addFragmentationListener(this);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AnalyzerListener#processAnalyzerEvent(org.jnetpcap.analysis.AnalyzerEvent)
	 */
	public void processAnalyzerEvent(FragmentSequenceEvent evt) {
		if (evt.getType() == FragmentSequenceEvent.Type.SEQUENCE_START) {
			hold(); // Hold the output queue until we reassemble
		}
		
		/*
		 * Check for error conditions. The reassembly will be aborted therefore
		 * we must release the hold we placed at the sequence start
		 */
		if (evt.getType() == FragmentSequenceEvent.Type.SEQUENCE_TIMEOUT ||
				evt.getType() == FragmentSequenceEvent.Type.SEQUENCE_FRAGMENT_OVERLAP) {
			release(); // Release the queue
		}

		/*
		 * All the PDU fragments have been seen and we can start our reassembly
		 */
		if (evt.getType() == FragmentSequenceEvent.Type.SEQUENCE_COMPLETE) {
			FragmentSequence seq = evt.getSequence();
			JPacket packet = createPacketFromSequence(seq);
			Ip4 ip = ipLocal1.get();

			if (packet.hasHeader(ip) && ip.hasAnalysis(reassembly)) {
				support.fire(FragmentReassemblyEvent
				    .createCompletePdu(this, reassembly));
			}

			/*
			 * Put on the inbound queue so it gets analyzed. This gives higher layer
			 * protocols complete PDUs for them to analyze and scanner to decode.
			 */
			Queue<JPacket> in = getInQueue();
			in.offer(packet);
			

			release();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AbstractAnalyzer#processPacket(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) {
		/*
		 * Do nothing, we are event driven.
		 */
		return true;
	}

	public <U> boolean addListener(
	    AnalyzerListener<FragmentReassemblyEvent> listener,
	    U user) {
		return this.support.addListener(listener, user);
	}

	public boolean removeListener(
	    AnalyzerListener<FragmentReassemblyEvent> listener) {
		return this.support.removeListener(listener);
	}
}
