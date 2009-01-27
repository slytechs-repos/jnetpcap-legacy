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

import org.jnetpcap.analysis.AbstractAnalysis;
import org.jnetpcap.analysis.JAnalysis;
import org.jnetpcap.nio.JMemory;

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

	public final static int FLAG_SACK_PERMITTED = 0x0001;

	public final static int FLAG_WINDOW_SCALING = 0x0002;

	public final static int FLAG_HAS_MSS = 0x0010;

	public final static int FLAG_HAS_WARNINGS = 0x1000;

	public final static int FLAG_HAS_ERRORS = 0x2000;

	private enum Field implements JStructField {
		WINDOW_SCALE,
		MSS,
		FLAGS,
		HASH,

		/**
		 * First sequence number seen in this TCP stream. Could be SYN generated or
		 * the first sequence of an already established stream.
		 */
		SEQUENCE,

		/**
		 * oldest unacknowledged sequence number by the sender
		 */
		SND_UNA,

		/**
		 * next sequence number to be sent
		 */
		SND_NXT,

		/**
		 * next sequence number expected on an incoming segment, and is the left or
		 * lower edge of the receive window
		 */
		RCV_NXT,

		/**
		 * RCV_NXT + RCV_WND = last sequence number expected on an incoming segment,
		 * and is the right or upper edge of the receive window
		 */
		RCV_WND,

		DPORT,

		DUPLEX_STREAM(REF), ;

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

	private static final String TITLE = "tcp stream";

	/**
	 * @param type
	 * @param size
	 */
	public TcpStream() {
		super(JMemory.Type.POINTER);
	}

	/**
	 * @param size
	 * @param name
	 */
	@SuppressWarnings("unchecked")
  public TcpStream(int hash) {
		super(TITLE, Field.class);

		setHashcode(hash);
	}

	@Override
	public int hashCode() {
		return super.getInt(Field.HASH.offset());
	}

	/**
	 * @param hash
	 */
	private void setHashcode(int hash) {
		super.setInt(Field.HASH.offset(), hash);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#getAnalysis(org.jnetpcap.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> T getAnalysis(T analysis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#hasAnalysis(org.jnetpcap.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#hasAnalysis(java.lang.Class)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(Class<T> analysis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * @param seq
	 */
	public void setSequenceStart(long sequence) {
		super.setUInt(Field.SEQUENCE.offset(), sequence);
	}

	public long getSequenceStart() {
		return super.getUInt(Field.SEQUENCE.offset());
	}

	/**
	 * @return
	 */
	public int getDestinationPort() {
		return super.getUShort(Field.DPORT.offset());
	}

	public void setDestinationPort(int value) {
		super.setUShort(Field.DPORT.offset(), value);
	}

	/**
   * @return the sndUNA
   */
  public final long getSndUNA() {
  	return getUInt(Field.SND_UNA.offset());
  }

	/**
   * @param sndUNA the sndUNA to set
   */
  public final void setSndUNA(long sndUNA) {
  	setUInt(Field.SND_UNA.offset(), sndUNA);
  }

	/**
   * @return the sndNXT
   */
  public final long getSndNXT() {
  	return getUInt(Field.SND_NXT.offset());
  }

	/**
   * @param sndNXT the sndNXT to set
   */
  public final void setSndNXT(long sndNXT) {
  	setUInt(Field.SND_NXT.offset(), sndNXT);
  }

	/**
   * @return the rcvNXT
   */
  public final long getRcvNXT() {
  	return getUInt(Field.RCV_NXT.offset());
  }

	/**
   * @param rcvNXT the rcvNXT to set
   */
  public final void setRcvNXT(long rcvNXT) {
  	setUInt(Field.RCV_NXT.offset(), rcvNXT);
  }

	/**
   * @return the rcvWIN
   */
  public final long getRcvWIN() {
  	return getUInt(Field.RCV_WND.offset());
  }

	/**
   * @param rcvWIN the rcvWIN to set
   */
  public final void setRcvWIN(long rcvWIN) {
  	super.setUInt(Field.RCV_WND.offset(), rcvWIN);
  }

}
