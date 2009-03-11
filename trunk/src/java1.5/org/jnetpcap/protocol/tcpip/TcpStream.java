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

import java.util.Comparator;
import java.util.Queue;
import java.util.concurrent.PriorityBlockingQueue;

import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.analysis.AbstractAnalysis;
import org.jnetpcap.packet.analysis.AnalyzerSupport;
import org.jnetpcap.packet.analysis.JAnalysis;
import org.jnetpcap.protocol.tcpip.TcpDuplexStream.Direction;
import org.jnetpcap.util.JThreadLocal;
import org.jnetpcap.util.Timeout;

/**
 * A stream in a single direction of a bi-directional stream. The parent of this
 * stream is a TcpDuplexStream, a stream consisting of 2 TcpStreams, one for
 * each direction.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpStream
    extends AbstractAnalysis<TcpStream, TcpStreamEvent> {

	private enum Field implements JStructField {
		DPORT(2),
		DUPLEX_STREAM(REF),
		FLAGS,
		HASH,

		MSS,

		/**
		 * RCV_NXT + RCV_WND = last sequence number expected on an incoming segment,
		 * and is the right or upper edge of the receive window
		 */
		RCV_WND,

		/**
		 * next sequence number to be sent
		 */
		SND_NXT,

		/**
		 * First sequence number seen in this TCP stream in the sender to receiver
		 * direction. Could be SYN generated or the first sequence of an already
		 * established stream.
		 */
		SND_START,

		/**
		 * oldest unacknowledged sequence number by the sender
		 */
		SND_UNA,

		WINDOW_SCALE, ;

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

	public final static int FLAG_HAS_ERRORS = 0x2000;

	public final static int FLAG_HAS_MSS = 0x0010;

	public final static int FLAG_HAS_WARNINGS = 0x1000;

	public final static int FLAG_SACK_PERMITTED = 0x0001;

	public final static int FLAG_WINDOW_SCALING = 0x0002;

	private static final String TITLE = "tcp stream";

	private final Queue<JPacket> bySequence =
	    new PriorityBlockingQueue<JPacket>(100, new Comparator<JPacket>() {
		    Tcp tcp1 = new Tcp();

		    Tcp tcp2 = new Tcp();

		    public int compare(JPacket o1, JPacket o2) {
			    if (o1.hasHeader(tcp1) && o2.hasHeader(tcp2)) {
				    return (int) (tcp1.seq() - tcp2.seq());
			    } else {
				    throw new IllegalStateException("A non TCP packet");
			    }
		    }

	    });

	private final Direction direction;

	private final TcpDuplexStream duplex;

	private final TcpAnalyzer analyzer;

	/**
	 * @param type
	 * @param size
	 */
	public TcpStream() {
		super(JMemory.Type.POINTER);
		this.direction = null;
		this.duplex = null;
		this.analyzer = null;
	}

	/**
	 * @param duplex
	 *          TODO
	 * @param size
	 * @param name
	 */
	@SuppressWarnings("unchecked")
	public TcpStream(int hash, Direction direction, TcpDuplexStream duplex,
	    TcpAnalyzer analyzer) {
		super(TITLE, Field.values());
		this.direction = direction;
		this.duplex = duplex;
		this.analyzer = analyzer;

		setHashcode(hash);
		setSndStart(0);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	public int compareTo(Timeout o) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalysis#getAnalysis(org.jnetpcap.packet.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> T getAnalysis(T analysis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * @return
	 */
	public int getDestinationPort() {
		return super.getUShort(Field.DPORT.offset());
	}

	/**
	 * @return the rcvWIN
	 */
	public final long getRcvWIN() {
		return getUInt(Field.RCV_WND.offset());
	}

	/**
	 * @return the sndNXT
	 */
	public final long getSndNXT() {
		return getUInt(Field.SND_NXT.offset());
	}

	/**
	 * @return the sndNXT
	 */
	public final long getSndNXTNormal() {
		return getUInt(Field.SND_NXT.offset()) - getSndStart();
	}

	public long getSndStart() {
		return super.getUInt(Field.SND_START.offset());
	}

	/**
	 * @return the sndUNA
	 */
	public final long getSndUNA() {
		return getUInt(Field.SND_UNA.offset());
	}

	/**
	 * @return the sndUNA
	 */
	public final long getSndUNANormal() {
		return getUInt(Field.SND_UNA.offset()) - getSndStart();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalysis#hasAnalysis(java.lang.Class)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(Class<T> analysis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalysis#hasAnalysis(org.jnetpcap.packet.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	@Override
	public int hashCode() {
		return super.getInt(Field.HASH.offset());
	}

	public boolean hasSndStart() {
		return (getSndStart() != 0);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.Timeout#isTimedout(long)
	 */
	public boolean isTimedout(long timeInMillis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	public void setDestinationPort(int value) {
		super.setUShort(Field.DPORT.offset(), value);
	}

	/**
	 * @param hash
	 */
	private void setHashcode(int hash) {
		super.setInt(Field.HASH.offset(), hash);
	}

	/**
	 * @param rcvWIN
	 *          the rcvWIN to set
	 */
	public final void setRcvWIN(long rcvWIN) {
		super.setUInt(Field.RCV_WND.offset(), rcvWIN);
	}

	/**
	 * @param sndNXT
	 *          the sndNXT to set
	 */
	public final void setSndNXT(long sndNXT) {
		setUInt(Field.SND_NXT.offset(), sndNXT);
	}

	/**
	 * @param sndNXT
	 *          the sndNXT to set
	 */
	public final void setSndNXT(long sndNXT, JPacket packet) {
		setUInt(Field.SND_NXT.offset(), sndNXT);

		addToSequenceQueue(packet);
	}

	/**
	 * @param seq
	 */
	public void setSndStart(long sequence) {
		super.setUInt(Field.SND_START.offset(), sequence);
	}

	/**
	 * @param sndUNA
	 *          the sndUNA to set
	 */
	public final void setSndUNA(long sndUNA, JPacket packet) {
		setUInt(Field.SND_UNA.offset(), sndUNA);
		removeFromSequenceQueue(sndUNA, new TcpAck(packet));
	}

	/**
	 * @param sndUNA
	 *          the sndUNA to set
	 */
	public final void setSndUNANormal(long sndUNA) {
		setUInt(Field.SND_UNA.offset(), sndUNA);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.util.Timeout#timeout()
	 */
	public void timeout() {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	public void addToSequenceQueue(JPacket packet) {

		Tcp tcp = new Tcp();
		// System.out.printf("QUEUE:%s:add(#%d: %d)\n", direction,
		// packet.getFrameNumber(),
		// packet.getHeader(tcp).seq() - getSndStart());

		bySequence.offer(packet);
	}

	private final JThreadLocal<Tcp> tcpLocal = new JThreadLocal<Tcp>(Tcp.class);

	/**
	 * Removes from queue segments that have lower sequence numbers then the one
	 * supplied. If analysis is not null, it is also applied to all the segments
	 * that are being removed from the queue at the same time.
	 * 
	 * @param sequence
	 *          timeout lower sequenced numbered segments
	 * @param analysis
	 *          apply analysis to each removed/timedout segment, if null ignored
	 * @return returns true if segments were removed from the queue otherwise
	 *         false
	 */
	public boolean removeFromSequenceQueue(long sequence, JAnalysis analysis) {
		if (bySequence.isEmpty()) {
			return false;
		}

		final Tcp tcp = tcpLocal.get();

		while (!bySequence.isEmpty()) {
			final JPacket packet = bySequence.peek();

			if (packet.hasHeader(tcp) && tcp.seq() <= sequence) {
				bySequence.poll();

				// System.out.printf("QUEUE:%s:remove(#%d: %d <= %d)\n", direction,
				// packet
				// .getFrameNumber(), tcp.seq() - getSndStart(), sequence -
				// getSndStart());

				if (analysis != null) {
					tcp.addAnalysis(analysis);

					TcpStreamEvent evt =
					    TcpStreamEvent.Type.ACKED_SEGMENT.create(analyzer, duplex, this,
					        packet);
					analyzer.getSupport().fire(evt);
				}
			} else {
				return false;
			}
		}

		return true;
	}

	public Queue<JPacket> getSequenceQueue() {
		return bySequence;
	}
}
