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

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.util.Timeout;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class FragmentSequence
    extends AbstractAnalysis<FragmentSequence, FragmentSequenceEvent> implements
    Timeout {

	private final static int PACKET_SEQUENCE = 0;

	private final static int SIZE = REF;

	private static final String NAME = "Fragment Sequence";

	private static final String NICNAME = "Frame";

	private boolean hasAllFragments = false;

	private FragmentSequenceAnalyzer analyzer;

	private long timeoutInMillis;

	/**
	 * @param size
	 */
	public FragmentSequence() {
		super(SIZE, NAME);

		setPacketSequence(new LinkedList<JPacket>());
	}

	/**
	 * @param type
	 * @param size
	 */
	public FragmentSequence(int a) {
		super(Type.POINTER, 0, NAME);
	}

	@SuppressWarnings("unchecked")
	public List<JPacket> getPacketSequence() {
		return super.getObject(List.class, PACKET_SEQUENCE);
	}

	private void setPacketSequence(List<JPacket> list) {
		super.setObject(PACKET_SEQUENCE, list);
	}

	public boolean hasAllFragments() {
		return hasAllFragments;
	}

	public void setHasAllFragments(boolean state) {
		this.hasAllFragments = state;
	}

	/**
	 * @return
	 */
	public boolean isEmpty() {
		return getPacketSequence().isEmpty();
	}

	/**
	 * @param packet
	 * @param offset
	 * @param length
	 */
	public void addFragment(JPacket packet, int offset, int length) {
		getPacketSequence().add(packet);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.Timeout#isTimedout(long)
	 */
	public boolean isTimedout(long timeInMillis) {
		return timeoutInMillis < timeInMillis;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.Timeout#timeout()
	 */
	public void timeout() {
		analyzer.timeout(this);
	}

	@Override
	public String getSummary() {
		StringBuilder b = new StringBuilder();
		for (JPacket packet : getPacketSequence()) {
			if (b.length() != 0) {
				b.append(", ");
			}

			b.append("#").append(packet.getState().getFrameNumber());
		}
		// return b.toString();
		return null;
	}

	@Override
	public String getNicName() {
		return NICNAME;
	}

	private Ip4 ip = new Ip4();

	@Override
	public Iterator<JAnalysis> iterator() {
		final Iterator<JPacket> seq = getPacketSequence().iterator();

		return new Iterator<JAnalysis>() {

			public boolean hasNext() {
				return seq.hasNext();
			}

			public JAnalysis next() {
				JPacket packet = seq.next();
				if (packet.hasHeader(ip)) {
					int start = ip.offset() * 8;
					int end = start + ip.length() - ip.hlen() * 4 -1;
					Set<Ip4.Flag> flags = ip.flagsEnum();
					
					return new AnalysisInfo("partial", "partial", "#"
					    + packet.getState().getFrameNumber() + " offset=" + start + "-"
					    + end + " len=" + ip.length() + ", flags=" + flags.toString());

				} else {
					return new AnalysisInfo("partial", "partial", "#"
					    + packet.getState().getFrameNumber());
				}
			}

			public void remove() {
				throw new UnsupportedOperationException("Not supported");
			}

		};
	}
}
