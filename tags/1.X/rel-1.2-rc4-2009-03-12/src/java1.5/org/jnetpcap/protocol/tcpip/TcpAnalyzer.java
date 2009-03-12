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
package org.jnetpcap.protocol.tcpip;

import java.util.HashMap;
import java.util.Map;
import java.util.Queue;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.analysis.AbstractAnalyzer;
import org.jnetpcap.packet.analysis.AnalyzerListener;
import org.jnetpcap.packet.analysis.AnalyzerSupport;
import org.jnetpcap.packet.analysis.JAnalyzer;
import org.jnetpcap.packet.analysis.JController;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.TcpDuplexStream.Direction;
import org.jnetpcap.util.JThreadLocal;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpAnalyzer
    extends AbstractAnalyzer {

	public enum Stage {
		FIN_COMPLETE,
		FIN_WAIT1,
		FIN_WAIT2,
		/**
		 * Stage not initialized
		 */
		NULL,
		SYN_COMPLETE,
		SYN_WAIT1,
		SYN_WAIT2,
	}

	private static final int PRIORITY = 100;

	private ThreadLocal<Ip4> ip1Local = new JThreadLocal<Ip4>(Ip4.class);

	private ThreadLocal<Ip4> ip2Local = new JThreadLocal<Ip4>(Ip4.class);

	private Map<Integer, TcpDuplexStream> streams =
	    new HashMap<Integer, TcpDuplexStream>();

	private AnalyzerSupport<TcpStreamEvent> support =
	    new AnalyzerSupport<TcpStreamEvent>();

	private ThreadLocal<Tcp> tcp1Local = new JThreadLocal<Tcp>(Tcp.class);

	private ThreadLocal<Tcp> tcp2Local = new JThreadLocal<Tcp>(Tcp.class);

	/**
	 * @param priority
	 */
	public TcpAnalyzer() {
		super(PRIORITY);
		
		JRegistry.getAnalyzer(JController.class).addAnalyzer(this, Tcp.ID);
	}

	/**
	 * @param priority
	 * @param parent
	 */
	public TcpAnalyzer(JAnalyzer parent) {
		super(PRIORITY, parent);
	}

	public <U> boolean addTcpStreamListener(
	    AnalyzerListener<TcpStreamEvent> listener,
	    U user) {
		return this.support.addListener(listener, user);
	}

	/**
	 * @param hash
	 * @return
	 */
	private TcpDuplexStream getDuplexStream(Tcp tcp, Ip4 ip4) {
		/*
		 * A duplex hashcode
		 */
		int duplexHash =
		    (ip4.destinationToInt() + tcp.destination())
		        ^ (ip4.sourceToInt() + tcp.source());

		/*
		 * Uni directional hashcode so we can identify which direction the packet is
		 * for
		 */
		int clientHash = (ip4.destinationToInt() + tcp.destination());
		int serverHash = (ip4.sourceToInt() + tcp.source());

		TcpDuplexStream duplex = streams.get(duplexHash);
		if (duplex == null) {
			duplex = new TcpDuplexStream(duplexHash, clientHash, serverHash, this);
			streams.put(duplexHash, duplex);
			duplex.getClientStream().setDestinationPort(tcp.destination());
			duplex.getServerStream().setDestinationPort(tcp.source());

			if (support.hasListeners()) {
				// support.fire(TcpStreamEvent.Type.DUPLEX_STREAM_OPEN
				// .create(this, duplex));
			}
		}

		return duplex;
	}

	/**
	 * @param packet
	 * @param tcp
	 * @param ip4
	 */
	private void initializeFromPacket(
	    TcpDuplexStream duplex,
	    JPacket packet,
	    Tcp tcp,
	    Ip4 ip4) {
		TcpStream sender = duplex.getForward(tcp);
		TcpStream receiver = duplex.getReverse(tcp);

		/*
		 * Direction: 1st packet seen is automatically the sender
		 */

		duplex.setStage(Stage.SYN_COMPLETE);

		sender.setSndStart(tcp.seq());
		sender.setSndNXT(tcp.seq() + 1, packet);
		sender.setSndUNA(tcp.seq(), null);

		if (tcp.flags_ACK()) {
			receiver.setSndStart(tcp.ack());
			receiver.setSndUNA(tcp.ack(), packet);

			receiver.setRcvWIN(tcp.window());
		}

	}

	private void printDebug(
	    String pre,
	    Direction printDir,
	    JPacket packet,
	    TcpDuplexStream duplex,
	    Tcp tcp,
	    int len) {

		/*
		 * foward/reverse from this packet's perspective
		 */
		TcpStream sender = duplex.getForward(tcp);
		TcpStream receiver = duplex.getReverse(tcp);

		long sseq = sender.getSndStart();
		long rseq = receiver.getSndStart();
		long seq = tcp.seq();
		long nseq = seq - sseq;
		long ack = tcp.ack();
		long nack = ack - rseq;
		long nxt = sender.getSndNXT();
		long una = sender.getSndUNA();

		Direction dir = duplex.getDirection(tcp);

		if (dir.equals(printDir)) {
			System.out.printf(
			    "%s#%d %s(%d):: nseq=%-4d seq=%-9d nack=%-4d len=%-4d :: ", pre,
			    packet.getFrameNumber(), dir, duplex.getServerStream()
			        .getDestinationPort(), nseq, seq, nack, len);

			System.out.printf("snd.nxt=%-4d snd.una=%-4d ", sender.getSndNXTNormal(),
			    sender.getSndUNANormal(), dir.inverse());

			System.out.printf(" snd.q=%d", sender.getSequenceQueue().size());
			System.out.printf(" snd.st=%d", sender.getSndStart());

			System.out.println();
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.AbstractAnalyzer#processPacket(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) throws TcpInvalidStreamHashcode {
		Tcp tcp = tcp1Local.get();
		Ip4 ip4 = ip1Local.get();

		if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
			int hash = processStream(packet, tcp, ip4);
		}

		return true;
	}

	/**
	 * @param packet
	 * @param tcp
	 * @throws TcpInvalidStreamHashcode
	 */
	private int processStream(JPacket packet, Tcp tcp, Ip4 ip4)
	    throws TcpInvalidStreamHashcode {

		/*
		 * A duplex hashcode
		 */
		int duplexHash =
		    (ip4.destinationToInt() + tcp.destination())
		        ^ (ip4.sourceToInt() + tcp.source());

		TcpDuplexStream duplex = getDuplexStream(tcp, ip4);

		// final int filter = 3179;
		// final int filter = 3306;
//		 final int filter = 3200;
//		if (tcp.destination() != filter && tcp.source() != filter) {
//			return duplexHash;
//		}

		// System.out.printf("#%-2d ", packet.getFrameNumber() + 1);

		tcp.addAnalysis(duplex);
		// System.out.printf("#%d: %s\n", packet.getFrameNumber(), tcp.toString());

		/*
		 * Check if its the first packet in 3-way handshake
		 */

		if (duplex.isInitialized() == false && tcp.flags_SYN() == false) {
			initializeFromPacket(duplex, packet, tcp, ip4);

		} else if (processTcp3WaySyn(packet, duplex, tcp, ip4)) {

		} else if (processTcp3WayFin(packet, duplex, tcp, ip4)) {
			// System.out.printf("client.queue=%d server.queue=%d\n", duplex
			// .getClientStream().getSequenceQueue().size(), duplex
			// .getServerStream().getSequenceQueue().size());
		} else if (processTcp(packet, duplex, tcp, ip4)) {

		} else {
			throw new IllegalStateException(
			    "oops shouldn't be here, not a TCP packet?");
		}

		return duplexHash;
	}

	private boolean processTcp(
	    JPacket packet,
	    TcpDuplexStream duplex,
	    Tcp tcp,
	    Ip4 ip4)

	{
		int len = ip4.length() - (ip4.hlen() + tcp.hlen()) * 4;

		return processTcp(packet, duplex, tcp, duplex.getForward(tcp), duplex
		    .getReverse(tcp), len);
	}

	/**
	 * @param packet
	 * @param duplex
	 * @param tcp
	 * @param sender
	 * @param receiver
	 *          TODO
	 * @param len
	 *          TODO
	 * @return
	 */
	private boolean processTcp(
	    JPacket packet,
	    TcpDuplexStream duplex,
	    Tcp tcp,
	    TcpStream sender,
	    TcpStream receiver,
	    int len) {

		processTcpSeq(packet, duplex, tcp, sender, receiver, len);
		processTcpAck(packet, duplex, tcp, sender, receiver, len);

		return true;
	}

	/**
	 * Modified 3way handshake for closing down the connection.
	 * 
	 * @param packet
	 * @param duplex
	 * @param tcp
	 * @param ip4
	 * @return
	 */
	private boolean processTcp3WayFin(
	    JPacket packet,
	    TcpDuplexStream duplex,
	    Tcp tcp,
	    Ip4 ip4) {

		/*
		 * Segment data length
		 */
		int len = ip4.length() - (ip4.hlen() + tcp.hlen()) * 4;

		Stage stage = duplex.getStage();
		TcpStream sender = duplex.getForward(tcp);
		TcpStream receiver = duplex.getReverse(tcp);

		long seq = tcp.seq();
		long ack = tcp.ack();

		if (tcp.flags_FIN() && (stage == Stage.SYN_COMPLETE || stage == Stage.NULL)) {
			duplex.setStage(Stage.FIN_WAIT1);
			duplex.setTime(getProcessingTime());

			if (support.hasListeners()) {
				support
				    .fire(TcpStreamEvent.Type.FIN_START.create(this, duplex, packet));
			}

			return processTcp(packet, duplex, tcp, ip4);

		} else if (tcp.flags_FIN() && stage == Stage.FIN_WAIT1) {
			duplex.setStage(Stage.FIN_WAIT2);
			// System.out
			// .printf("delta=%d us\n", getProcessingTime() - duplex.getTime());

			return true;

		} else if (!tcp.flags_FIN() && stage == Stage.FIN_WAIT2) {
			duplex.setStage(Stage.FIN_COMPLETE);
			// System.out
			// .printf("delta=%d us\n", getProcessingTime() - duplex.getTime());
			// System.out.printf("FIN_COMPLETE: transfer stats: client=%d bytes,
			// server=%d bytes\n",
			// duplex.getClientStream().getSndNXTNormal() - 2,
			// duplex.getServerStream()
			// .getSndNXTNormal() - 2);

			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.FIN_COMPLETE.create(this, duplex,
				    packet));
			}

			return true;
		}

		return false;
	}

	/**
	 * 3way handshake for opening up the TCP connection
	 * 
	 * @param packet
	 * @param duplex
	 * @param tcp
	 * @param ip4
	 * @return
	 */
	private boolean processTcp3WaySyn(
	    JPacket packet,
	    TcpDuplexStream duplex,
	    Tcp tcp,
	    Ip4 ip4) {

		// System.out.printf("%s seq=%d ack=%d\n", duplex.getDirection(tcp),
		// tcp.seq(), tcp.ack());
		TcpStream client = duplex.getClientStream();
		TcpStream server = duplex.getServerStream();

		if (tcp.flags_SYN() && !tcp.flags_ACK()) {

			/*
			 * Direction: client ==> server
			 */

			duplex.setStage(Stage.SYN_WAIT1);

			client.setSndStart(tcp.seq());
			client.setSndUNA(tcp.seq(), packet);
			client.setSndNXT(tcp.seq());

			if (support.hasListeners()) {
				support
				    .fire(TcpStreamEvent.Type.SYN_START.create(this, duplex, packet));
			}

			return processTcp(packet, duplex, tcp, client, server, 1);

		} else if (tcp.flags_ACK() && tcp.flags_SYN()
		    && duplex.getStage() == Stage.SYN_WAIT1) {

			/*
			 * Direction: server ==> client
			 */

			duplex.setStage(Stage.SYN_WAIT2);

			server.setSndStart(tcp.seq());
			server.setSndUNA(tcp.seq(), packet);
			server.setSndNXT(tcp.seq());

			// System.out.println(Stage.SYN_WAIT2.toString());

			return processTcp(packet, duplex, tcp, server, client, 1);

		} else if (tcp.flags_ACK() && !tcp.flags_SYN()
		    && duplex.getStage() == Stage.SYN_WAIT2) {

			/*
			 * Direction: client ==> server
			 */

			duplex.setStage(Stage.SYN_COMPLETE);

			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.SYN_COMPLETE.create(this, duplex,
				    packet));
			}

			return processTcp(packet, duplex, tcp, ip4);
		}

		return false;
	}

	private Direction display = Direction.NONE;

	/**
	 * Process a regular segment. We get window, ACK, SEQUENCE and data updates in
	 * regular segments. In addition we can get RST signal and out of band data.
	 * 
	 * @param packet
	 * @param duplex
	 * @param tcp
	 * @param sender
	 * @param receiver
	 *          TODO
	 * @param len
	 *          TODO
	 * @return
	 */
	private boolean processTcpAck(
	    JPacket packet,
	    TcpDuplexStream duplex,
	    Tcp tcp,
	    TcpStream sender,
	    TcpStream receiver,
	    int len) {

		if (tcp.flags_ACK() == false) {
			return false;
		}

		long sseq = sender.getSndStart();
		long rseq = receiver.getSndStart();
		long seq = tcp.seq();
		long ack = tcp.ack();

		Direction dir = duplex.getDirection(tcp);

		printDebug("ACK:", display, packet, duplex, tcp, len);

		/*
		 * Now handle the ACKs which signal to the tcp stream in reverse direction.
		 */
		if (false && receiver.getSndUNA() == ack) {
			/*
			 * Duplicate ACK
			 */
			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.DUPLICATE_ACK.create(this, duplex,
				    packet));
			}

		} else if (false && receiver.getSndUNA() > ack) {
			/*
			 * Error: ACKed a historically ACKed and advanced segments
			 */
			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.OLD_ACK.create(this, duplex, packet));
			}

		} else if (receiver.getSndNXT() < ack) {
			/*
			 * Warning: ACKed a segment that hasn't been sent yet
			 */
			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.ACK_FOR_UNSEEN_SEGMENT.create(this,
				    duplex, packet));
			}

			receiver.setSndNXT(ack);
			receiver.setSndUNA(ack, packet);

		} else {

			receiver.setSndUNA(ack, packet);
			receiver.setRcvWIN(tcp.windowScaled());
			if (support.hasListeners()) {
				 support.fire(TcpStreamEvent.Type.ACK.create(this, duplex, packet));
			}

		}

		// processWinUpdate(forward, tcp);

		return true;
	}

	/**
	 * Process a regular segment. We get window, ACK, SEQUENCE and data updates in
	 * regular segments. In addition we can get RST signal and out of band data.
	 * 
	 * @param packet
	 * @param duplex
	 * @param tcp
	 * @param sender
	 * @param receiver
	 *          TODO
	 * @param len
	 *          TODO
	 * @return
	 */
	private boolean processTcpSeq(
	    JPacket packet,
	    TcpDuplexStream duplex,
	    Tcp tcp,
	    TcpStream sender,
	    TcpStream receiver,
	    int len) {

		long sseq = sender.getSndStart();
		long rseq = receiver.getSndStart();
		long seq = tcp.seq();
		long nseq = seq - sseq;
		long ack = tcp.ack();
		long nack = ack - rseq;
		long nxt = sender.getSndNXT();
		long una = sender.getSndUNA();

		Direction dir = duplex.getDirection(tcp);

		printDebug("SEQ:", display, packet, duplex, tcp, len);

		if (seq > nxt) {

			/*
			 * Don't advance snd.nxt but put the packet on the timeout/sequence queue
			 */
			sender.addToSequenceQueue(packet);

			/*
			 * Out of order segment
			 */
			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.OUT_OF_ORDER_SEGMENT.create(this,
				    duplex, packet));
			}
		} else if (false && una > seq) {
			/*
			 * Duplicate segment
			 */
			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.DUPLICATE_SEGMENT.create(this, duplex,
				    packet));
			}
		} else {

			/*
			 * In sequence new segment
			 */

			receiver.setRcvWIN(tcp.window());

			if (len > 0) {
				long n = sender.getSndNXT() + len + 1; // NXT points to +1, not last
				// seq

				/*
				 * Now check to see if there are existing segments in the queue that can
				 * be sequentially combined (holes filled) so that we can skip ahead in
				 * nxt sequence number to the last contigues sequence number. Remember
				 * the queue is a sorted set on sequence number.
				 */
				Queue<JPacket> queue = sender.getSequenceQueue();
				Tcp tcp2 = tcp2Local.get();
				Ip4 ip = ip2Local.get();
				for (JPacket p : queue) {
					if (p.hasHeader(tcp2) && tcp2.seq() + 1 == n && packet.hasHeader(ip)) {
						n += tcp2.getPayloadLength();
					} else {
						break;
					}
				}

				sender.setSndNXT(n, packet);
				if (support.hasListeners()) {
					// support.fire(TcpStreamEvent.Type.NEW_SEQUENCE.create(this, duplex,
					// packet));
				}
			}
		}

		return true;
	}

	public boolean removeListener(AnalyzerListener<TcpStreamEvent> listener) {
		return this.support.removeListener(listener);
	}

	/**
   * @return
   */
  public AnalyzerSupport<TcpStreamEvent> getSupport() {
  	return support;
  }
}
