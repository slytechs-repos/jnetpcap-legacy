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
import org.jnetpcap.packet.analysis.AbstractAnalysis;
import org.jnetpcap.packet.analysis.JAnalysis;

/**
 * Tcp acknowledgement analysis.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TcpAck
    extends
    AbstractAnalysis<TcpAck, TcpStreamEvent> {

	private enum Field implements JStructField {
		PACKET(REF), ;
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

	/**
	 * @param type
	 */
	public TcpAck() {
		super(Type.POINTER);
	}

	/**
	 * @param c
	 */
	public TcpAck(JPacket packet) {
		super(Field.values());

		setPacket(packet);
	}

	/**
	 * @param packet
	 */
	public void setPacket(JPacket packet) {
		super.setObject(Field.PACKET.offset(), packet);
	}

	public JPacket getPacket() {
		return super.getObject(JPacket.class, Field.PACKET.offset());
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.analysis.JAnalysis#hasAnalysis(org.jnetpcap.packet.analysis.JAnalysis)
	 */
	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
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

}
