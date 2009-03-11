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
package org.jnetpcap.packet.analysis;

import java.util.Iterator;

import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JPacket;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class FragmentAssembly
    extends AbstractAnalysis<FragmentAssembly, FragmentAssemblyEvent> {

	private final static String TITLE = "Fragment Reassembly";

	public enum Field implements JStructField {
		PACKET_SEQUENCE(REF),
		PACKET(REF), ;

		private final int len;

		int offset;

		private Field() {
			this(4);
		}

		private Field(int len) {
			this.len = len;
		}

		public int length(int offset) {
			this.offset = offset;
			return this.len;
		}

		public final int offset() {
			return offset;
		}
	}

	/**
	 * @param size
	 * @param name
	 */
	public FragmentAssembly(JPacket packet, FragmentSequence sequence) {
		super(TITLE, Field.values());

		setFragmentSequence(sequence);
		setPacket(packet);
	}

	private void setFragmentSequence(FragmentSequence sequence) {
		super.setObject(Field.PACKET_SEQUENCE.offset(), sequence);
	}

	public FragmentSequence getFragmentSequence() {
		return super.getObject(FragmentSequence.class, Field.PACKET_SEQUENCE
		    .offset());
	}

	/**
	 * @param type
	 * @param size
	 * @param name
	 */
	public FragmentAssembly() {
		super(JMemory.Type.POINTER);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalysis#getAnalysis(org.jnetpcap.packet.analysis.JAnalysis)
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
	 * @see org.jnetpcap.packet.analysis.JAnalysis#hasAnalysis(org.jnetpcap.packet.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		return super.hasAnalysis(analysis.getType());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalysis#hasAnalysis(java.lang.Class)
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
		return super.getObject(JPacket.class, Field.PACKET.offset());
	}

	public void setPacket(JPacket packet) {
		super.setObject(Field.PACKET.offset(), packet);
	}
}
