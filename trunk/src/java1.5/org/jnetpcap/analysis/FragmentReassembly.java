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

import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JPacket;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class FragmentReassembly
    extends AbstractAnalysis<FragmentReassembly, FragmentReassemblyEvent> {

	private final static String NAME = "Fragment Reassembly";

	public enum Field implements AnalysisField {
		PACKET_SEQUENCE(0, REF),
		PACKET(REF, REF),
		LAST(REF + REF, 0), ;
		private final int len;

		private final int offset;

		private Field() {
			this(0, 4);
		}

		private Field(int offset, int len) {
			this.len = len;
			this.offset = offset;
		}

		public final int getLength() {
			return this.len;
		}

		public final int getOffset() {
			return this.offset;
		}
	}

	/**
	 * @param size
	 * @param name
	 */
	public FragmentReassembly(JPacket packet, FragmentSequence sequence) {
		super(Field.LAST.getOffset(), NAME);

		setFragmentSequence(sequence);
		setPacket(packet);
	}

	private void setFragmentSequence(
	    AbstractAnalysis<FragmentSequence, FragmentSequenceEvent> sequence) {
		super.setObject(Field.PACKET_SEQUENCE.getOffset(), sequence);
	}

	public AbstractAnalysis<FragmentSequence, FragmentSequenceEvent> getFragmentSequence() {
		return super.getObject(FragmentSequence.class, Field.PACKET_SEQUENCE
		    .getOffset());
	}

	/**
	 * @param type
	 * @param size
	 * @param name
	 */
	public FragmentReassembly() {
		super(JMemory.Type.POINTER, REF, NAME);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getAnalysis(org.jnetpcap.analysis.JAnalysis)
	 */
	@SuppressWarnings("unchecked")
	public <T extends JAnalysis> T getAnalysis(T analysis) {
		if (analysis.getType() == AnalysisUtils.getType(FragmentSequence.class)) {
			return (T) getFragmentSequence();
		} else {
			return null;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#hasAnalysis(org.jnetpcap.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		return super.hasAnalysis(analysis.getType());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#hasAnalysis(java.lang.Class)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(Class<T> analysis) {
		return super.hasAnalysis(AnalysisUtils.getType(analysis));
	}

	@Override
	public Iterator<JAnalysis> iterator() {
		return getFragmentSequence().iterator();
	}

	/**
	 * @return
	 */
	public JPacket getPacket() {
		return super.getObject(JPacket.class, Field.PACKET.getOffset());
	}

	public void setPacket(JPacket packet) {
		super.setObject(Field.PACKET.getOffset(), packet);
	}
	
}
