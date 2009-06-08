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
 * Main controller for an analyzer graph network. JController is the root of any
 * analyzis hierarchy. Protocol analyzer register themselves with JController
 * which control which analyzers receive events and packets. JController also
 * manages several resources needed by sub-analyzers such as input and output
 * packet queues.
 * <p>
 * A typical hierarchy of analyzers looks like the following tree:
 * 
 * <pre>
 * JController
 *  +-&gt; StatisticsAnalyzer
 *  +-&gt; Ip4Analyzer
 *  |    +-&gt; Ip4Sequencer
 *  |    +-&gt; Ip4Assembler
 *  |
 *  +-&gt; TcpAnalyzer
 *  |    +-&gt; TcpSequencer
 *  |    +-&gt; TcpAssembler
 *  |    
 *  +-&gt; HttpAnalyzer
 *  +-&gt; SipAnalyzer
 * </pre>
 * 
 * </p>
 * JController implements JPacketHandler interface and is typically setup to
 * receive packets from <code>Pcap.loop</code> or <code>Pcap.dispatch</code>
 * methods. The received packets flow through the controller and its
 * sub-analyzers based on analyzer types.
 * <p>
 * There are 2 types of analyzers. Packet and protocol analyzers. Packet
 * analyzer is interested in the entire packet such as
 * <code>StatisticsAnalyzer</code> whereas protocol analyzer is interested in
 * specific protocol headers within the packet. Packet analyzers always receive
 * all packets and protocol analyzers receive only those packets that contain
 * the specific headers they are interested in. For example
 * <code>Ip4Analyzer</code> tells JController that its only interested in
 * packets containing <code>ip4</code> header. JController will efficiently
 * dispatch only those packets that contain Ip4 header to Ip4Analyzer.
 * </p>
 * <p>
 * Packets flow within JController from an "input queue" to an "output queue".
 * JController provides a register method for <code>JPacketHandler</code>
 * listeners which would like to receive packets from JController's output
 * queue. This queue may contain different set of packets then the one that
 * JController received from packet dispatcher method. Analyzer's can intercept
 * or inject packets onto the output queue. Also the timing of the packets
 * received from JContoller may be altered. Most analyzers tell JController to
 * buffer packets until certain conditions are met or until the analyzer that
 * put a hold on the output queue releases it. This allows analyzers to analyze
 * packets as they come in and report errors, perform reassembly and otherwise
 * put a wait on the output queue until all the packets arrive. This ability to
 * put the output queue on hold allows analyzers to handle incomplete, damaged,
 * out of order streams of packets and many other types of protocol related
 * conditions.
 * </p>
 * <p>
 * JRegistry maintains a default analyzer hierarchy. This default hierachy is
 * used for by default when using pcap's dispatcher methods. However this
 * hierarchy can be modified globally or separate custom ones setup. For example
 * you can setup your own private analyzer tree with analyzers which have been
 * configured for a specific purpose. This private analyzer tree does not in any
 * way affect the global default one maintained by JRegistry. You can even pass
 * packets from one analyzer tree to another breaking up the sequence how
 * analysis is applied to packets. Also you can disable the default analysis
 * tree completely and through a custom packet handler dispatch various
 * pre-screened analysis tasks to specific analyzer trees using multiple-threads
 * for example.
 * </p>
 * <p>
 * JController allows multiple analyzers to be registered for the same protocol
 * header. Each analyzer being registered provides a priority number which is
 * used to determine in which order the analyzers receive packets they need to
 * handle from JController. Analyzers can be enabled and disabled at runtime without
 * having to use the unregister method. 
 * </p>
 * <p>
 * JController provides a vital property to all the analyzer's which is the
 * processing timestamp. This timestamp by default is based on the timestamp
 * extracted from the packet currently being processed. Optionally the packet's 
 * timestamp can be overriden by current live time or custom time controller
 * provided by the user. 
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unchecked")
public class JController
    extends
    AbstractAnalyzer implements JPacketHandler<Pcap>, JControllerOptions {

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
		dispatchWorker = new BlockingQueuePump<JPacket>("out_queue_pump", 1000) {

			@Override
			protected void dispatch(JPacket packet) {
				support.fireNextPacket(packet);
			}

		};

	}

	public <T extends JProtocolHandler> void addHandler(T handler) {

		return;
	}

	public static <T extends JProtocolHandler, E extends Enum<? extends E>> boolean addHandler(
	    T handler,
	    Set<E> options) {

		return false;
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
				// bq.put(packet);
				dispatchWorker.put(packet);
				// Thread.sleep(100);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			// dispatchWorker.dispatchQueue.run();
		}
	}

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

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JControllerOptions#consumePackets(boolean)
	 */
	public boolean consumePackets(boolean enabled) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JControllerOptions#enableAnalysis(boolean)
	 */
	public boolean enableAnalysis(boolean state) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JControllerOptions#enablePacketAnalysis(boolean)
	 */
	public boolean enablePacketAnalysis(boolean state) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JControllerOptions#enableProtocolAnalysis(boolean)
	 */
	public boolean enableProtocolAnalysis(boolean state) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

}
