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

import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.analysis.AbstractAnalysis;
import org.jnetpcap.packet.analysis.JAnalysis;
import org.jnetpcap.protocol.tcpip.TcpAnalyzer.Stage;

/**
 * The main tcp stream analysis object that keeps global properties about a tcp
 * stream. It also consists of 2 uni-directional streams, that descrive various
 * properties of the tcp stream in a single direction.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpDuplexStream
    extends AbstractAnalysis<TcpDuplexStream, TcpStreamEvent> {

	public enum Direction {
		BOTH,
		CLIENT,
		NONE,
		SERVER;

		/**
		 * Provides a custom equals method, that takes into account the constant
		 * BOTH and always matches if compared against either in self or supplied
		 * parameter.
		 * 
		 * @param dir
		 *          direction to match
		 * @return true if directions are equal and always true matching against
		 *         BOTH constant
		 */
		public boolean equals(Direction dir) {
			if (this == BOTH || dir == BOTH) {
				return true;
			}

			return dir == this;
		}

		/**
		 * Returns the inverse constant of this one. If BOTH is the constant, then
		 * NONE is returned as its inverse.
		 * 
		 * @return opposite meaning CONSTANT of this one
		 */
		public Direction inverse() {
			if (this == BOTH) {
				return NONE;
			}

			if (this == CLIENT) {
				return SERVER;
			} else {
				return CLIENT;
			}
		}
	}

	private enum Field implements JStructField {
		CLIENT_STREAM(REF),
		FLAGS,
		HASH(8),
		SEQUENCE,

		SERVER_STREAM(REF),
		STAGE, ;

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

	public final static int FLAG_HAS_FIN = 0x0002;

	public final static int FLAG_HAS_SYNCH = 0x0001;

	public final static int FLAG_HAS_WARNINGS = 0x1000;

	private static final String TITLE = "tcp duplex stream";

	private long processingTime;

	/**
	 * @param type
	 * @param size
	 */
	public TcpDuplexStream() {
		super(JMemory.Type.POINTER);
	}

	/**
	 * @param support
	 *          TODO
	 * @param type
	 * @param size
	 * @param name
	 */
	protected TcpDuplexStream(int hash, int client, int server,
	    TcpAnalyzer analyzer) {
		super(TITLE, Field.values());
		setClient(new TcpStream(client, Direction.CLIENT, this, analyzer));
		setServer(new TcpStream(server, Direction.SERVER, this, analyzer));
		setHashcode(hash);
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

	public TcpStream getClientStream() {
		return super.getObject(TcpStream.class, Field.CLIENT_STREAM.offset());
	}

	public Direction getDirection(Tcp tcp) {
		if (getClientStream().getDestinationPort() == tcp.destination()) {
			return Direction.CLIENT;
		} else {
			return Direction.SERVER;
		}

	}

	public TcpStream getForward(int uniHash) throws TcpInvalidStreamHashcode {
		TcpStream stream = getClientStream();
		if (stream.hashCode() == uniHash) {
			return stream;

		} else if ((stream = getServerStream()).hashCode() == uniHash) {
			return stream;

		} else {
			throw new TcpInvalidStreamHashcode();
		}
	}

	public TcpStream getForward(Tcp tcp) {
		if (getClientStream().getDestinationPort() == tcp.destination()) {
			return getClientStream();
		} else {
			return getServerStream();
		}
	}

	public TcpStream getReverse(int uniHash) throws TcpInvalidStreamHashcode {
		final TcpStream stream = getClientStream();
		if (stream.hashCode() == uniHash) {
			return getServerStream();

		} else if (getServerStream().hashCode() == uniHash) {
			return stream;

		} else {
			throw new TcpInvalidStreamHashcode();
		}
	}

	public TcpStream getReverse(Tcp tcp) {
		if (getClientStream().getDestinationPort() == tcp.destination()) {
			return getServerStream();
		} else {
			return getClientStream();
		}
	}

	public TcpStream getServerStream() {
		return super.getObject(TcpStream.class, Field.SERVER_STREAM.offset());
	}

	public Stage getStage() {
		return Stage.values()[getInt(Field.STAGE.offset)];
	}

	public long getTime() {
		return this.processingTime;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalysis#hasAnalysis(java.lang.Class)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(Class<T> analysis) {
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalysis#hasAnalysis(org.jnetpcap.packet.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		return false;
	}

	@Override
	public int hashCode() {
		return super.getInt(Field.HASH.offset());
	}

	public boolean isInitialized() {
		return getStage() != Stage.NULL;
	}

	private void setClient(TcpStream stream) {
		super.setObject(Field.CLIENT_STREAM.offset(), stream);
	}

	/**
	 * @param hash
	 */
	private void setHashcode(int hash) {
		super.setInt(Field.HASH.offset(), hash);
	}

	private void setServer(TcpStream stream) {
		super.setObject(Field.SERVER_STREAM.offset(), stream);
	}

	/**
	 * @param syn_wait1
	 */
	public void setStage(Stage stage) {
		setInt(Field.STAGE.offset(), stage.ordinal());
	}

	/**
	 * @param processingTime
	 */
	public void setTime(long processingTime) {
		this.processingTime = processingTime;
	}
	
	public String toString() {
		TcpStream client = getClientStream();
		TcpStream server = getServerStream();
		
		return "" + server.getDestinationPort() + " <-> " + client.getDestinationPort();
	}

	/**
   * @param tcp
   * @return
   */
  public long getNormalizedSequence(Tcp tcp) {
		if (getClientStream().getDestinationPort() == tcp.destination()) {
			return tcp.seq() - getClientStream().getSndStart();
		} else {
			return tcp.seq() - getServerStream().getSndStart();
		}
  }

	/**
   * @param tcp
   * @return
   */
  public long getNormalizedAck(Tcp tcp) {
  	if (tcp.flags_ACK() == false) {
  		return 0;
  	}
  	
		if (getClientStream().getDestinationPort() == tcp.destination()) {
			return tcp.ack() - getServerStream().getSndStart();
		} else {
			return tcp.ack() - getClientStream().getSndStart();
		}
  }
}
