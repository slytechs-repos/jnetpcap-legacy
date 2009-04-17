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
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class StatisticAnalyzer {

	public static String[] allLabels() {
		final String[] labels = new String[JRegistry.MAX_ID_COUNT];

		for (int i = 0; i < JProtocol.WEB_IMAGE_ID; i++) {
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

	private final AtomicLong[] counters = new AtomicLong[JRegistry.MAX_ID_COUNT];

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

	public long[] snapshot() {
		final long[] copy = new long[this.counters.length];

		for (int i = 0; i < this.counters.length; i++) {
			copy[i] = this.counters[i].get();
		}

		return copy;
	}

	public long total() {
		return this.total.get();
	}
}
