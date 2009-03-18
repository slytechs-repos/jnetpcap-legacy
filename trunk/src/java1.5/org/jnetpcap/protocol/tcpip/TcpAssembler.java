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

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JMemoryPool;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.analysis.AbstractAnalyzer;
import org.jnetpcap.packet.analysis.AnalysisException;
import org.jnetpcap.packet.analysis.AnalyzerListener;
import org.jnetpcap.packet.analysis.AnalyzerSupport;
import org.jnetpcap.packet.analysis.FragmentAssembler;
import org.jnetpcap.packet.analysis.FragmentAssembly;
import org.jnetpcap.packet.analysis.FragmentAssemblyEvent;
import org.jnetpcap.packet.analysis.FragmentSequence;
import org.jnetpcap.packet.analysis.FragmentSequenceEvent;
import org.jnetpcap.util.JThreadLocal;

/**
 * Tcp reassembler. Assembles sequences of tcp segments into a contigues stream
 * of data. TcpAssembler works with TcpSequencer to reassemble portions of the
 * tcp segments. Higher level protocol must specify which portions of the tcp
 * stream to reassemble.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpAssembler
    extends
    AbstractAnalyzer
    implements
    FragmentAssembler,
    AnalyzerListener<FragmentSequenceEvent> {

	private final AnalyzerSupport<FragmentAssemblyEvent> support =
	    new AnalyzerSupport<FragmentAssemblyEvent>();

	/**
	 * 
	 */
	public TcpAssembler() {

		JRegistry.getAnalyzer(TcpSequencer.class).addFragmentationListener(this);
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
	 * @see org.jnetpcap.packet.analysis.AnalyzerSupport#addListener(org.jnetpcap.packet.analysis.AnalyzerListener,
	 *      java.lang.Object)
	 */
	public <U> boolean addReassemblyListener(
	    AnalyzerListener<FragmentAssemblyEvent> listener,
	    U user) {
		return this.support.addListener(listener, user);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.AnalyzerListener#processAnalyzerEvent(org.jnetpcap.packet.analysis.AnalyzerEvent)
	 */
	public void processAnalyzerEvent(FragmentSequenceEvent evt) {
		if (evt.getType() == FragmentSequenceEvent.Type.SEQUENCE_COMPLETE) {

			FragmentSequence sequence = evt.getSequence();
			if (sequence.isEmpty()) {
				return; // Nothing to do
			}

			JPacket packet = reassemble(sequence);

			FragmentAssembly assembly = new FragmentAssembly(packet, sequence);

			JPacket first = sequence.getPacketSequence().get(0); // 1st packet
			Tcp tcp = tcpLocal.get();
			if (first.hasHeader(tcp)) {
				tcp.addAnalysis(assembly);
			}

			support.fire(FragmentAssemblyEvent.createCompletePdu(this, assembly));

			release();
		} else if (evt.getType() == FragmentSequenceEvent.Type.SEQUENCE_START) {
			hold();
		}
	}

	private final static JMemoryPool memory = new JMemoryPool();

	private static final JThreadLocal<Tcp> tcpLocal =
	    new JThreadLocal<Tcp>(Tcp.class);

	// private final JThreadLocal<Ip4> ipLocal = new JThreadLocal<Ip4>(Ip4.class);

	private JPacket reassemble(FragmentSequence sequence) {
		JBuffer buf = new JBuffer(JMemory.Type.POINTER);
		memory.allocate(sequence.getTotalLength(), buf);
		Tcp tcp = tcpLocal.get();
		// Ip4 ip = ipLocal.get();
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
	 * @see org.jnetpcap.packet.analysis.AbstractAnalyzer#processPacket(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) throws AnalysisException {
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * @param listener
	 * @return
	 * @see org.jnetpcap.packet.analysis.AnalyzerSupport#removeListener(org.jnetpcap.packet.analysis.AnalyzerListener)
	 */
	public boolean removeReassemblyListener(
	    AnalyzerListener<FragmentAssemblyEvent> listener) {
		return this.support.removeListener(listener);
	}

}
