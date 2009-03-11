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

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.analysis.AbstractAnalyzerEvent;
import org.jnetpcap.packet.analysis.AnalyzerEvent.AnalyzerEventType;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpStreamEvent
    extends AbstractAnalyzerEvent<TcpStreamEvent.Type> {

	private final TcpStream stream;

	private final TcpDuplexStream duplex;

	private final JPacket packet;

	public enum Type implements AnalyzerEventType {
		DUPLEX_STREAM_OPEN,
		SYN_START,
		SYN_COMPLETE,
		STREAM_CLOSED,
		FIN_START,
		FIN_COMPLETE,
		DUPLICATE_ACK,
		OLD_ACK,
		ACK_FOR_UNSEEN_SEGMENT,
		ACK,
		OUT_OF_ORDER_SEGMENT,
		DUPLICATE_SEGMENT,
		NEW_SEQUENCE,
		ACKED_SEGMENT, ;

		public TcpStreamEvent create(
		    TcpAnalyzer source,
		    TcpDuplexStream duplex,
		    TcpStream stream,
		    JPacket packet) {
			return new TcpStreamEvent(source, this, duplex, stream, packet);
		}

		public TcpStreamEvent create(
		    TcpAnalyzer source,
		    TcpDuplexStream duplex,
		    JPacket packet) {
			return new TcpStreamEvent(source, this, duplex, packet);
		}

		public TcpStreamEvent create(TcpAnalyzer source, TcpDuplexStream duplex) {
			return new TcpStreamEvent(source, this, duplex);
		}

	}

	public TcpStreamEvent(TcpAnalyzer source, Type type, TcpDuplexStream duplex,
	    TcpStream stream, JPacket packet) {
		super(source, type);

		this.duplex = duplex;
		this.packet = packet;
		this.stream = stream;
	}

	public TcpStreamEvent(TcpAnalyzer source, Type type, TcpDuplexStream duplex,
	    JPacket packet) {
		super(source, type);

		this.duplex = duplex;
		this.packet = packet;
		this.stream = null;
	}

	public TcpStreamEvent(TcpAnalyzer source, Type type, TcpDuplexStream duplex) {
		super(source, type);

		this.duplex = duplex;
		this.stream = null;
		this.packet = null;
	}

	/**
	 * @param source
	 * @param type
	 */
	public TcpStreamEvent(TcpAnalyzer source, Type type, TcpStream stream) {
		super(source, type);

		this.stream = stream;
		this.duplex = null;
		this.packet = null;
	}

	public final TcpStream getStream() {
		return this.stream;
	}

	/**
	 * @return
	 */
	public JPacket getPacket() {
		return packet;
	}

	/**
	 * @return the duplex
	 */
	public final TcpDuplexStream getDuplex() {
		return this.duplex;
	}

	@Override
  public int hashCode() {
		return this.duplex.hashCode();
  }

	/**
   * @return
   */
  public int uniDirectionalHashCode() {
  	return packet.getHeader(new Tcp()).uniHashCode();
  }
	
	
}
