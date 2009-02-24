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

import org.jnetpcap.analysis.AbstractAnalyzer;
import org.jnetpcap.analysis.AnalyzerListener;
import org.jnetpcap.analysis.AnalyzerSupport;
import org.jnetpcap.analysis.FragmentReassembly;
import org.jnetpcap.analysis.FragmentAssembler;
import org.jnetpcap.analysis.FragmentReassemblyEvent;
import org.jnetpcap.analysis.FragmentSequence;
import org.jnetpcap.analysis.FragmentSequenceEvent;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JMemoryPool;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.packet.header.Tcp;
import org.jnetpcap.util.JThreadLocal;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpAssembler
    extends AbstractAnalyzer implements FragmentAssembler,
    AnalyzerListener<FragmentSequenceEvent> {

	private final AnalyzerSupport<FragmentReassemblyEvent> support =
	    new AnalyzerSupport<FragmentReassemblyEvent>();

	/**
	 * 
	 */
	public TcpAssembler() {

		JRegistry.getAnalyzer(TcpSequencer.class)
		    .addFragmentationListener(this);
	}

	/**
	 * @param priority
	 * @param parent
	 */
	public TcpAssembler(TcpSequencer parent) {
		super(300, parent);

		parent.addFragmentationListener(this);
	}

	/**
	 * @param <U>
	 * @param listener
	 * @param user
	 * @return
	 * @see org.jnetpcap.analysis.AnalyzerSupport#addListener(org.jnetpcap.analysis.AnalyzerListener,
	 *      java.lang.Object)
	 */
	public <U> boolean addReassemblyListener(
	    AnalyzerListener<FragmentReassemblyEvent> listener,
	    U user) {
		return this.support.addListener(listener, user);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AnalyzerListener#processAnalyzerEvent(org.jnetpcap.analysis.AnalyzerEvent)
	 */
	public void processAnalyzerEvent(FragmentSequenceEvent evt) {
		if (evt.getType() == FragmentSequenceEvent.Type.SEQUENCE_COMPLETE) {

			FragmentSequence sequence = evt.getSequence();
			if (sequence.isEmpty()) {
				return; // Nothing to do
			}

			JPacket packet = reassemble(sequence);

			FragmentReassembly assembly = new FragmentReassembly(packet, sequence);

			JPacket first = sequence.getPacketSequence().get(0); // 1st packet
			Tcp tcp = tcpLocal.get();
			if (first.hasHeader(tcp)) {
				tcp.addAnalysis(assembly);
			}

			support.fire(FragmentReassemblyEvent.createCompletePdu(this, assembly));

			release();
		} else if (evt.getType() == FragmentSequenceEvent.Type.SEQUENCE_START) {
			hold();
		}
	}

	private final JMemoryPool memory = new JMemoryPool();

	private final JThreadLocal<Tcp> tcpLocal = new JThreadLocal<Tcp>(Tcp.class);

	private final JThreadLocal<Ip4> ipLocal = new JThreadLocal<Ip4>(Ip4.class);

	private JPacket reassemble(FragmentSequence sequence) {
		JBuffer buf = new JBuffer(JMemory.Type.POINTER);
		memory.allocate(sequence.getTotalLength(), buf);
		Tcp tcp = tcpLocal.get();
		Ip4 ip = ipLocal.get();
		long start = sequence.getStart();

		for (JPacket p : sequence.getPacketSequence()) {
			if (p.hasHeader(tcp)) {
				int seq = (int) (tcp.seq() - start);
				int offset = tcp.getOffset() + tcp.hlen() * 4;
				int length = tcp.getPayloadLength();

				p.transferTo(buf, offset, length, seq);
			} else {
				throw new IllegalStateException(
				    "expected tcp header binding in tcp packet");
			}
		}

		JPacket packet = sequence.getPacketSequence().get(0);
		int i = packet.getState().findHeaderIndex(Tcp.ID);
		int nid = packet.getState().getHeaderIdByIndex(i + 1);

		packet = new JMemoryPacket(nid, buf);

		return packet;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AbstractAnalyzer#processPacket(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) throws AnalysisException {
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * @param listener
	 * @return
	 * @see org.jnetpcap.analysis.AnalyzerSupport#removeListener(org.jnetpcap.analysis.AnalyzerListener)
	 */
	public boolean removeReassemblyListener(
	    AnalyzerListener<FragmentReassemblyEvent> listener) {
		return this.support.removeListener(listener);
	}

}
