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

import org.jnetpcap.analysis.AbstractAnalyzer;
import org.jnetpcap.analysis.AnalyzerListener;
import org.jnetpcap.analysis.AnalyzerSupport;
import org.jnetpcap.analysis.JAnalyzer;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.packet.header.Tcp;
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

	private ThreadLocal<Ip4> ip4Local = new JThreadLocal<Ip4>(Ip4.class);

	private Map<Integer, TcpDuplexStream> streams =
	    new HashMap<Integer, TcpDuplexStream>();

	private AnalyzerSupport<TcpStreamEvent> support =
	    new AnalyzerSupport<TcpStreamEvent>();

	private ThreadLocal<Tcp> tcpLocal = new JThreadLocal<Tcp>(Tcp.class);

	/**
	 * @param priority
	 */
	public TcpAnalyzer() {
		super(PRIORITY);
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
			duplex = new TcpDuplexStream(duplexHash, clientHash, serverHash);
			streams.put(duplexHash, duplex);

			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.DUPLEX_STREAM_OPEN
				    .create(this, duplex));
			}
		}

		return duplex;
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
	private boolean processFin3WayHandshake(
	    JPacket packet,
	    TcpDuplexStream duplex,
	    Tcp tcp,
	    Ip4 ip4) {

		System.out.println("stage=" + duplex.getStage());
		Stage stage = duplex.getStage();

		if (tcp.flags_FIN() && (stage == Stage.SYN_COMPLETE || stage == Stage.NULL)) {
			duplex.setStage(Stage.FIN_WAIT1);
			duplex.setTime(getProcessingTime());
			duplex.getClientStream().setSequenceStart(tcp.seq());

			if (support.hasListeners()) {
				support
				    .fire(TcpStreamEvent.Type.FIN_START.create(this, duplex, packet));
			}

			return true;

		} else if (tcp.flags_FIN() && stage == Stage.FIN_WAIT1) {
			duplex.setStage(Stage.FIN_WAIT2);
			System.out
			    .printf("delta=%d us\n", getProcessingTime() - duplex.getTime());

			return true;

		} else if (!tcp.flags_FIN() && stage == Stage.FIN_WAIT2) {
			duplex.setStage(Stage.FIN_COMPLETE);
			System.out
			    .printf("delta=%d us\n", getProcessingTime() - duplex.getTime());
			System.out.printf("FIN_COMPLETE=%d\n", tcp.seq()
			    - duplex.getForward(tcp).getSequenceStart());

			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.FIN_COMPLETE.create(this, duplex,
				    packet));
			}

			return true;
		}

		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.AbstractAnalyzer#processPacket(org.jnetpcap.packet.JPacket)
	 */
	@Override
	public boolean processPacket(JPacket packet) throws InvalidStreamHashcode {
		Tcp tcp = tcpLocal.get();
		Ip4 ip4 = ip4Local.get();

		if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
			int hash = processStream(packet, tcp, ip4);
		}

		return true;
	}

	/**
	 * Process a regular segment. We get window, ACK, SEQUENCE and data updates in
	 * regular segments. In addition we can get RST signal and out of band data.
	 * 
	 * @param packet
	 * @param duplex
	 * @param tcp
	 * @param ip4
	 * @return
	 */
	private boolean processSegment(
	    JPacket packet,
	    TcpDuplexStream duplex,
	    Tcp tcp,
	    Ip4 ip4) {

		/*
		 * Segment data length
		 */
		int len = ip4.length() - (ip4.hlen() + tcp.hlen()) << 2;

		/*
		 * foward/reverse from this packet's perspective
		 */
		TcpStream forward = duplex.getForward(tcp);
		TcpStream reverse = duplex.getReverse(tcp);

		if (forward.getRcvNXT() < tcp.seq()) {
			/*
			 * Out of order segment
			 */
			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.OUT_OF_ORDER.create(this, duplex,
				    packet));
			}
		} else if (forward.getRcvNXT() > tcp.seq()) {
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

			forward.setRcvNXT(tcp.seq());
			forward.setSndNXT(tcp.seq() + len);
			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.NEW_SEQUENCE.create(this, duplex,
				    packet));
			}
		}

		if (tcp.flags_ACK()) {
			if (reverse.getSndUNA() == tcp.ack()) {
				/*
				 * Duplicate ACK
				 */
				if (support.hasListeners()) {
					support.fire(TcpStreamEvent.Type.DUPLICATE_ACK.create(this, duplex,
					    packet));
				}

			} else if (reverse.getSndUNA() > tcp.ack()) {
				/*
				 * Error: ACKed a historically ACKed and advanced segments
				 */
				if (support.hasListeners()) {
					support.fire(TcpStreamEvent.Type.OLD_ACK.create(this, duplex,
					    packet));
				}

			} else if (reverse.getSndNXT() < tcp.ack()) {
				/*
				 * Error: ACKed a segment that hasn't been sent yet
				 */
				if (support.hasListeners()) {
					support.fire(TcpStreamEvent.Type.FUTURE_ACK.create(this, duplex,
					    packet));
				}
			} else {

				reverse.setRcvNXT(tcp.ack());
				if (support.hasListeners()) {
					support.fire(TcpStreamEvent.Type.ACK.create(this, duplex,
					    packet));
				}

			}
		}

		// processWinUpdate(forward, tcp);

		return true;
	}

	/**
	 * @param packet
	 * @param tcp
	 * @throws InvalidStreamHashcode
	 */
	private int processStream(JPacket packet, Tcp tcp, Ip4 ip4)
	    throws InvalidStreamHashcode {

		/*
		 * A duplex hashcode
		 */
		int duplexHash =
		    (ip4.destinationToInt() + tcp.destination())
		        ^ (ip4.sourceToInt() + tcp.source());

		TcpDuplexStream duplex = getDuplexStream(tcp, ip4);

		tcp.addAnalysis(duplex);
		// System.out.printf("#%d: %s\n", packet.getFrameNumber(), tcp.toString());

		/*
		 * Check if its the first packet in 3-way handshake
		 */

		if (processSyn3WayHandshake(packet, duplex, tcp, ip4)) {

		} else if (processFin3WayHandshake(packet, duplex, tcp, ip4)) {

		} else if (processSegment(packet, duplex, tcp, ip4)) {

		} else {
			throw new IllegalStateException(
			    "oops shouldn't be here, not a TCP packet?");
		}

		return duplexHash;
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
	private boolean processSyn3WayHandshake(
	    JPacket packet,
	    TcpDuplexStream duplex,
	    Tcp tcp,
	    Ip4 ip4) {
		if (tcp.flags_SYN() && !tcp.flags_ACK()) {
			duplex.setStage(Stage.SYN_WAIT1);
			duplex.getForward(tcp).setRcvNXT(tcp.seq());
			if (support.hasListeners()) {
				support
				    .fire(TcpStreamEvent.Type.SYN_START.create(this, duplex, packet));
			}

			TcpStream client = duplex.getClientStream();
			client.setSequenceStart(tcp.seq());

			return true;

		} else if (tcp.flags_ACK() && tcp.flags_SYN()
		    && duplex.getStage() == Stage.SYN_WAIT1) {
			duplex.setStage(Stage.SYN_WAIT2);
			
			duplex.getForward(tcp).setRcvNXT(tcp.seq());
			duplex.getReverse(tcp).setRcvNXT(tcp.ack());
			
			TcpStream server = duplex.getServerStream();
			server.setSequenceStart(tcp.seq());

			return true;

		} else if (tcp.flags_ACK() && !tcp.flags_SYN()
		    && duplex.getStage() == Stage.SYN_WAIT2) {
			duplex.setStage(Stage.SYN_COMPLETE);

			duplex.getForward(tcp).setRcvNXT(tcp.seq());
			duplex.getReverse(tcp).setRcvNXT(tcp.ack());
			
			if (support.hasListeners()) {
				support.fire(TcpStreamEvent.Type.SYN_COMPLETE.create(this, duplex,
				    packet));
			}

			return true;
		}

		return false;
	}

	public boolean removeListener(AnalyzerListener<TcpStreamEvent> listener) {
		return this.support.removeListener(listener);
	}
}
