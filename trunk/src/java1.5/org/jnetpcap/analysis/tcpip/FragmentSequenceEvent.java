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

import org.jnetpcap.analysis.AbstractAnalyzerEvent;
import org.jnetpcap.analysis.AnalyzerEvent.AnalyzerEventType;
import org.jnetpcap.packet.JPacket;

public class FragmentSequenceEvent
    extends AbstractAnalyzerEvent<FragmentSequenceEvent.Type> {

	public enum Type implements AnalyzerEventType {
		SEQUENCE_COMPLETE,
		SEQUENCE_FRAGMENT_OVERLAP,
		SEQUENCE_NEW_PACKET,
		SEQUENCE_START,
		SEQUENCE_TIMEOUT
	}

	public static FragmentSequenceEvent sequenceComplete(
	    FragmentSequenceAnalyzer source,
	    FragmentSequence sequence) {
		return new FragmentSequenceEvent(source, Type.SEQUENCE_COMPLETE, sequence);
	}

	public static FragmentSequenceEvent sequenceNewPacket(
	    FragmentSequenceAnalyzer source,
	    FragmentSequence sequence,
	    JPacket packet) {
		return new FragmentSequenceEvent(source, Type.SEQUENCE_NEW_PACKET,
		    sequence, packet);
	}

	public static FragmentSequenceEvent sequenceStart(
	    FragmentSequenceAnalyzer source,
	    FragmentSequence sequence) {
		return new FragmentSequenceEvent(source, Type.SEQUENCE_START, sequence);
	}

	public static FragmentSequenceEvent sequenceTimeout(
	    FragmentSequenceAnalyzer source,
	    FragmentSequence sequence) {
		return new FragmentSequenceEvent(source, Type.SEQUENCE_TIMEOUT, sequence);
	}

	private JPacket packet;

	private FragmentSequence sequence;

	/**
	 * @param source
	 */
	public FragmentSequenceEvent(FragmentSequenceAnalyzer source,
	    FragmentSequenceEvent.Type type) {
		super(source, type);
	}

	public FragmentSequenceEvent(FragmentSequenceAnalyzer source,
	    FragmentSequenceEvent.Type type, FragmentSequence sequence) {
		super(source, type);
		this.sequence = sequence;
	}

	/**
	 * @param source
	 * @param type
	 * @param sequence
	 * @param packet
	 */
	public FragmentSequenceEvent(FragmentSequenceAnalyzer source, Type type,
	    FragmentSequence sequence, JPacket packet) {
		this(source, type, sequence);
		this.packet = packet;

	}

	public final JPacket getPacket() {
  	return this.packet;
  }

	public final FragmentSequence getSequence() {
  	return this.sequence;
  }

}