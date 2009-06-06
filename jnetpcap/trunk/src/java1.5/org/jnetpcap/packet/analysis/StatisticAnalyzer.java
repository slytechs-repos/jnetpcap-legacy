/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.packet.analysis;

import java.util.concurrent.atomic.AtomicLong;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.UnregisteredHeaderException;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.protocol.JProtocol;

/**
 * Statics analyzer that keeps track of how many packets and how many headers of
 * each protocol its seen. The analyzer maintains a table of per protocol header
 * counters and a global packet counter. Since StatisticAnalyzer is multi-thread
 * safe, it keeps track of data in thread safe structures and requires a user to
 * take a snapshot of the current state of the statistics table. The snapshot is
 * a copy of the table or a snapshot of the statistic information at a specific
 * time which the working table may continue to be modified by other threads.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class StatisticAnalyzer implements Statistics, JPacketHandler<Object> {

	private final static int COUNT = JProtocol.values().length;

	public static String[] allLabels() {
		final String[] labels = new String[JRegistry.MAX_ID_COUNT];

		for (int i = 0; i < JProtocol.LAST_ID; i++) {
			labels[i] = JProtocol.valueOf(i).name();
		}

		for (int i = 0; i < JRegistry.MAX_ID_COUNT; i++) {
			if (labels[i] != null) {
				continue;
			}
			try {
				final AnnotatedHeader a = JRegistry.lookupAnnotatedHeader(i);
				labels[i] = a.getNicname();
			} catch (final UnregisteredHeaderException e) {
			}
		}

		return labels;
	}

	private final AtomicLong[] counters = new AtomicLong[COUNT];

	private JPacketHandler<Object> handler;

	private final AtomicLong total = new AtomicLong(0L);

	private Object data;

	/**
	 * Initialize counters table for all possible protocols. This ensures that we
	 * will be able to count for all protocol types, even future ones
	 */
	{
		for (int i = 0; i < this.counters.length; i++) {
			this.counters[i] = new AtomicLong(0L);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.Statistics#labels()
	 */
	public String[] labels() {
		return allLabels();
	}

	public void processPacket(final JPacket packet) {
		this.total.incrementAndGet();

		final JPacket.State state = packet.getState();

		final int size = state.getHeaderCount();

		for (int i = 0; i < size; i++) {
			final int id = state.getHeaderIdByIndex(i);

			this.counters[id].incrementAndGet();
		}

		if (this.handler != null) {
			this.handler.nextPacket(packet, this.data);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.Statistics#reset()
	 */
	public void reset() {
		this.total.set(0L);

		for (final AtomicLong element : this.counters) {
			element.set(0L);
		}
	}

	@SuppressWarnings("unchecked")
	public final void setHandler(
	    final JPacketHandler<?> handler,
	    final Object data) {
		this.handler = (JPacketHandler<Object>) handler;
		this.data = data;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.Statistics#snapshot()
	 */
	public long[] snapshot() {
		final long[] copy = new long[COUNT];

		for (int i = 0; i < COUNT; i++) {
			copy[i] = this.counters[i].get();
		}

		return copy;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.Statistics#total()
	 */
	public long total() {
		return this.total.get();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.Statistics#size()
	 */
	public int size() {

		return COUNT;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JPacketHandler#nextPacket(org.jnetpcap.packet.JPacket,
	 *      java.lang.Object)
	 */
	public void nextPacket(JPacket packet, Object user) {
		processPacket(packet);
	}
}
