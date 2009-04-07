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

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jnetpcap.analysis.AbstractPeerableAnalysis;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.util.Timeout;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class FragmentSequence
    extends AbstractPeerableAnalysis<FragmentSequence, FragmentSequenceEvent>
    implements Timeout {

	private final List<JPacket> packetSequence =
	    Collections.synchronizedList(new LinkedList<JPacket>());

	private JPacket current;

	private AtomicBoolean hasAllFragments = new AtomicBoolean(false);
	
	private FragmentSequenceAnalyzer analyzer;

	public JPacket getCurrent() {
		return this.current;
	}

	public void setCurrent(JPacket current) {
		this.current = current;
	}

	public List<JPacket> getPacketSequence() {
		return this.packetSequence;
	}

	public boolean hasAllFragments() {
		return hasAllFragments.get();
	}

	public void setHasAllFragments(boolean state) {
		this.hasAllFragments.set(state);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AbstractPeerableAnalysis#reset()
	 */
	@Override
	protected void initAfterPeer() {
		packetSequence.clear();
		current = null;
	}

	/**
	 * @return
	 */
	public boolean isEmpty() {
		return packetSequence.isEmpty();
	}

	/**
	 * @param packet
	 * @param offset
	 * @param length
	 */
	public void addFragment(JPacket packet, int offset, int length) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/* (non-Javadoc)
   * @see org.jnetpcap.analysis.Timeout#isTimedout(long)
   */
  public boolean isTimedout(long timeInMillis) {
	  // TODO Auto-generated method stub
	  throw new UnsupportedOperationException("Not implemented yet");
  }

	/* (non-Javadoc)
   * @see org.jnetpcap.analysis.Timeout#timeout()
   */
  public void timeout() {
  	analyzer.timeout(this);
  }
}
