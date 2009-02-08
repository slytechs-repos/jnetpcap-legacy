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

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.jnetpcap.analysis.AbstractAnalyzer;
import org.jnetpcap.analysis.AnalyzerListener;
import org.jnetpcap.analysis.AnalyzerSupport;
import org.jnetpcap.analysis.FragmentSequence;
import org.jnetpcap.analysis.FragmentSequenceAnalyzer;
import org.jnetpcap.analysis.FragmentSequenceEvent;
import org.jnetpcap.analysis.JAnalyzer;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.util.JLogger;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AbstractFragmentationAnalyzer
    extends AbstractAnalyzer implements FragmentSequenceAnalyzer {

	private static final int SIZE = 500;

	static final Logger logger = JLogger.getLogger(Ip4FragmentationAnalyzer.class);

	protected final Map<Integer, FragmentSequence> fragmentation =
	    new HashMap<Integer, FragmentSequence>(SIZE);

	protected final AnalyzerSupport<FragmentSequenceEvent> fragSupport =
	    new AnalyzerSupport<FragmentSequenceEvent>();

	long timeout = DEFAULT_FRAGMENT_TIMEOUT;

	private long time;

	/**
	 * 
	 */
	public AbstractFragmentationAnalyzer() {
		super();
	}

	/**
	 * @param priority
	 */
	public AbstractFragmentationAnalyzer(int priority) {
		super(priority);
	}

	/**
	 * @param priority
	 * @param parent
	 */
	public AbstractFragmentationAnalyzer(int priority, JAnalyzer parent) {
		super(priority, parent);
	}

	protected FragmentSequence getSequence(int hash, boolean create) {
		/*
		 * Sorted by ip offset
		 */
		FragmentSequence sequence = fragmentation.get(hash);
		if (sequence == null && create) {
			sequence = new FragmentSequence(hash, this);
			sequence.setTimeout(getProcessingTime() + timeout);

			fragmentation.put(hash, sequence);
//			getTimeoutQueue().add(sequence);

//			System.out.printf("hash=%x %x\n", hash, new Integer(hash).hashCode());
		fragSupport.fire(FragmentSequenceEvent.sequenceStart(this, sequence));
		}

		return sequence;

	}

	public boolean addFragmentationListener(
	    AnalyzerListener<FragmentSequenceEvent> listener) {
		return this.fragSupport.addListener(listener, null);
	}

	public boolean removeFragmentationListener(
	    AnalyzerListener<FragmentSequenceEvent> listener) {
		return this.fragSupport.removeListener(listener);
	}

	public void timeout(FragmentSequence analysis) {
  	if (fragmentation.remove(analysis.hashCode()) == null) {
  		logger.warning("Unable to remove analysis info from fragmentation map");
  	}
  
  	fragSupport.fire(FragmentSequenceEvent.sequenceTimeout(this, analysis));
  }

	protected void setProcessingTime(JPacket packet) {
  	this.time = packet.getCaptureHeader().timestampInMillis();
  }

	/* (non-Javadoc)
   * @see org.jnetpcap.analysis.AbstractAnalyzer#getProcessingTime()
   */
  @Override
  public long getProcessingTime() {
  	return this.time;
  }

}