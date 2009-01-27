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
import org.jnetpcap.analysis.tcpip.TcpAnalyzer.Stage;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.header.Tcp;

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

	private enum Field implements JStructField {
		CLIENT_STREAM(REF),
		FLAGS,
		HASH(8),
		STAGE,

		SEQUENCE,
		SERVER_STREAM(REF), 
		;

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
	 * @param type
	 * @param size
	 * @param name
	 */
	@SuppressWarnings("unchecked")
  protected TcpDuplexStream(int hash, int client, int server) {
		super(TITLE, Field.class);

		setClient(new TcpStream(client));
		setServer(new TcpStream(server));
		setHashcode(hash);
	}

	/**
	 * @param hash
	 */
	private void setHashcode(int hash) {
		super.setInt(Field.HASH.offset(), hash);
	}

	@Override
	public int hashCode() {
		return super.getInt(Field.HASH.offset());
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

	public TcpStream getClientStream() {
		return super.getObject(TcpStream.class, Field.CLIENT_STREAM.offset());
	}

	public TcpStream getServerStream() {
		return super.getObject(TcpStream.class, Field.SERVER_STREAM.offset());
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.analysis.JAnalysis#hasAnalysis(org.jnetpcap.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	private void setClient(TcpStream stream) {
		super.setObject(Field.CLIENT_STREAM.offset(), stream);
	}

	private void setServer(TcpStream stream) {
		super.setObject(Field.SERVER_STREAM.offset(), stream);
	}

	public TcpStream getForward(Tcp tcp) {
		if (getClientStream().getDestinationPort() == tcp.destination()) {
			return getClientStream();
		} else {
			return getServerStream();
		}
	}

	public TcpStream getReverse(Tcp tcp) {
		if (getClientStream().getDestinationPort() != tcp.destination()) {
			return getServerStream();
		} else {
			return getClientStream();
		}
	}

	public TcpStream getForward(int uniHash) throws InvalidStreamHashcode {
		TcpStream stream = getClientStream();
		if (stream.hashCode() == uniHash) {
			return stream;

		} else if ((stream = getServerStream()).hashCode() == uniHash) {
			return stream;

		} else {
			throw new InvalidStreamHashcode();
		}
	}

	public TcpStream getReverse(int uniHash) throws InvalidStreamHashcode {
		final TcpStream stream = getClientStream();
		if (stream.hashCode() == uniHash) {
			return getServerStream();

		} else if (getServerStream().hashCode() == uniHash) {
			return stream;

		} else {
			throw new InvalidStreamHashcode();
		}
	}

	/**
	 * @param syn_wait1
	 */
	public void setStage(Stage stage) {
		setInt(Field.STAGE.offset(), stage.ordinal());
	}

	public Stage getStage() {
		return Stage.values()[getInt(Field.STAGE.offset)];
	}

	/**
	 * @param processingTime
	 */
	public void setTime(long processingTime) {
		this.processingTime = processingTime;
	}

	public long getTime() {
		return this.processingTime;
	}
}
