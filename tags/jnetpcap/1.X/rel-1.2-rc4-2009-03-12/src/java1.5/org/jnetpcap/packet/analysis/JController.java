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

import java.util.Comparator;
import java.util.LinkedList;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.util.BlockingQueuePump;
import org.jnetpcap.util.JLogger;
import org.jnetpcap.util.JPacketSupport;
import org.jnetpcap.util.TimeoutQueue;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unchecked")
public class JController
    extends AbstractAnalyzer implements JPacketHandler<Pcap> {

	private final static Logger logger = JLogger.getLogger(JController.class);

	private final static int INITIAL_CAPACITY = 1000;

	private final static Comparator<JAnalyzer> ANALYZER_PRIORITY =
	    new Comparator<JAnalyzer>() {

		    public int compare(JAnalyzer o1, JAnalyzer o2) {
			    return o1.getPriority() - o2.getPriority();
		    }

	    };

	private long analyzerMap = 0;

	private Set<JAnalyzer>[] analyzers = new TreeSet[JRegistry.MAX_ID_COUNT];

	private long bufferSize = Long.MAX_VALUE;

	private Queue<JPacket> inQ =
	    new PriorityQueue<JPacket>(INITIAL_CAPACITY, PACKET_TIMESTAMP);

	private int lock;

	private Queue<JPacket> outQ =
	    new PriorityQueue<JPacket>(INITIAL_CAPACITY, JController.PACKET_TIMESTAMP);

	private BlockingQueuePump<JPacket> dispatchWorker;

	private final static Comparator<JPacket> PACKET_TIMESTAMP =
	    new Comparator<JPacket>() {

		    public int compare(JPacket o1, JPacket o2) {
			    int r =
			        (int) (o1.getCaptureHeader().timestampInNanos() - o2
			            .getCaptureHeader().timestampInNanos());
			    // final long M = 0x00FFFFFF;
			    //
			    // System.out.printf("%d/%d - %d/%d = %d\n",
			    // o1.getFrameNumber(),
			    // o1.getCaptureHeader().timestampInNanos() & M,
			    // o2.getFrameNumber(),
			    // o2.getCaptureHeader()
			    // .timestampInNanos() & M, r);

			    if (r == 0) {
				    return (int) (o1.getFrameNumber() - o2.getFrameNumber());
			    } else {
				    return r;
			    }
		    }

	    };

	private final JPacketSupport support = new JPacketSupport();

	private long timeInMillis;

	private TimeoutQueue timeQueue = new TimeoutQueue();

	private long totalBuffered = 0;

	public JController() {
		dispatchWorker = 
	    new BlockingQueuePump<JPacket>("out_queue_pump", 1000) {

	    @Override
	    protected void dispatch(JPacket packet) {
	    	support.fireNextPacket(packet);
	    }

    };

	}

	public <T> boolean add(JPacketHandler<T> o, T user) {
		return this.support.add(o, user);
	}

	public void addAnalyzer(JAnalyzer analyzer, int id) {
		analyzerMap |= (1L << id);

		getAnalyzers(id).add(analyzer);
		analyzer.setParent(this);
	}

	public Set<JAnalyzer> getAnalyzers(int id) {
		if (analyzers[id] == null) {
			analyzers[id] = new TreeSet<JAnalyzer>(JController.ANALYZER_PRIORITY);
		}

		return analyzers[id];
	}

	public final long getBufferSize() {
		return this.bufferSize;
	}

	@Override
	public Queue<JPacket> getInQueue() {
		return inQ;
	}

	@Override
	public Queue<JPacket> getOutQueue() {
		return outQ;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalyzer#getPriority()
	 */
	public int getPriority() {
		return 0; // Highest priority
	}

	@Override
	public long getProcessingTime() {
		return this.timeInMillis;
	}

	@Override
	public TimeoutQueue getTimeoutQueue() {
		return this.timeQueue;
	}

	@Override
	public int hold() {
		return this.lock++;
	}

	public void nextPacket(JPacket packet, Pcap pcap) {

		packet = new PcapPacket(packet);

		/*
		 * Set the curren time from the packet stream
		 */
		setProcessingTime(packet);

		/*
		 * Process the timeout queue and timeout any entries based on the latest
		 * time
		 */
		timeQueue.timeout(getProcessingTime());

		/*
		 * Put the packet on the inbound queue to be processed
		 */
		inQ.offer(packet); // inQ is sorted by capture timestamp

		/*
		 * Process the inbound queue of packets
		 */
		processInboundQueue();

		/**
		 * Process the outbound queue of packets
		 */
		processingOutboundQueue();
	}

	public boolean processHeaders(JPacket packet) {
		long map = packet.getState().get64BitHeaderMap(0);

		return processHeaders(packet, map);
	}

	public boolean processHeaders(JPacket packet, long map) {
		if ((map & analyzerMap) == 0) {
			return true; // No analyzers matching headers in the packet
		}

		int count = packet.getHeaderCount();
		map &= analyzerMap; // Just leave the analyzers from the map
		for (int i = 0; i < count && map != 0; i++) {
			int id = packet.getHeaderIdByIndex(i);
			if ((map & (1L << id)) == 0) {
				continue;
			}

			/*
			 * Turn off the analyzer ID bit we just processed. This allows us to check
			 * entire map and end loop quickly if no more analyzers are present for
			 * current header map
			 */
			map &= ~(1L << id);

			/*
			 * Now go through all the analyzers for this protocol, sorted by priority
			 */
			for (JAnalyzer analyzer : analyzers[id]) {
				try {
					analyzer.processPacket(packet);
				} catch (AnalysisException e) {
					logger.log(Level.WARNING, e.getMessage(), e);
				}
			}
		}

		return true;
	}

	private Queue<JPacket> consumeQ = new LinkedList<JPacket>();

	protected void processInboundQueue() {

		while (inQ.isEmpty() == false) {
			JPacket p = inQ.poll();

			setProcessingTime(p);
			processPacket(p);

			totalBuffered += p.getTotalSize();

			/*
			 * Now check if this packet is to be consumed (if its found on the consume
			 * queue). If consumed we simply discard the packet by not putting it on
			 * the outbound queue.
			 */
			if (true || consumeQ.isEmpty() || consumeQ.remove(p) == false) {
				outQ.offer(p);
			} else {
				System.out.printf("consumed=%d\n", p.getFrameNumber());
			}
		}
	}

	protected void processingOutboundQueue() {

		while ((this.lock == 0 || totalBuffered > bufferSize)
		    && outQ.isEmpty() == false) {
			JPacket packet = outQ.poll();
			totalBuffered -= packet.getTotalSize();

			/*
			 * Dispatch using a QueuePump which uses a bg thread. Therefore we never
			 * block here
			 */
			try {
//				bq.put(packet);
				dispatchWorker.put(packet);
//				Thread.sleep(100);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
//			dispatchWorker.dispatchQueue.run();
		}
	}
	
	private BlockingQueue<JPacket> bq = new ArrayBlockingQueue<JPacket>(1000);

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.AbstractAnalyzer#processPacket(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) {
		long map = packet.getState().get64BitHeaderMap(0);

		return processHeaders(packet, map);
	}

	@Override
	public int release() {
		this.lock--;
		if (lock == 0) {
			processingOutboundQueue();
		}

		return lock + 1;
	}

	public boolean remove(JPacketHandler<?> o) {
		return this.support.remove(o);
	}

	public final void setBufferSize(long bufferSize) {
		this.bufferSize = bufferSize;
	}

	protected void setProcessingTime(JPacket packet) {
		this.timeInMillis = packet.getCaptureHeader().timestampInMillis();
	}

	@Override
	public void consumePacket(JPacket packet) {
		if (consumeQ.contains(packet) == false) {
			consumeQ.add(packet);
		}
	}

}
