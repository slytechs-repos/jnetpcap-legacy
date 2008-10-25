/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.packet;

import java.nio.ByteOrder;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;

public abstract class JHeader
    extends JBuffer {

	/**
	 * Peered state of a header
	 * 
	 * <pre>
	 * typedef struct header_t {
	 * 	int32_t hdr_id; // header ID
	 * 	uint32_t hdr_offset; // offset into the packet_t-&gt;data buffer
	 * 	int32_t hdr_length; // length of the header in packet_t-&gt;data buffer
	 * } header_t;
	 * 
	 * </pre>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class State
	    extends JStruct {

		public final static String STRUCT_NAME = "header_t";

		/**
		 * @param structName
		 */
		public State() {
			super(STRUCT_NAME);
		}

		public native int getId();

		public native int getOffset();

		public native int getLength();

		public int peer(State peer) {
			if (peer.isDirect() == false) {
				throw new IllegalStateException(
				    "DirectState can only peer with another DirectState");
			}
			return super.peer(peer);
		}

		public boolean isDirect() {
			return true;
		}

		public String toString() {
			return "(id=" + getId() + ", offset=" + getOffset() + ", length="
			    + getLength() + ")";
		}
	}

	protected final State state;

	protected JPacket packet;

	private final int id;

	public JHeader(int id) {
		this.id = id;
		this.state = new State();
		super.order(ByteOrder.nativeOrder());
	}

	public JHeader(State state) {
		this.state = state;
		this.id = state.getId();
		super.order(ByteOrder.nativeOrder());
	}

	public void decode() {
		// Empty - subclasses can override
	}

	public State getState() {
		return state;
	}

	public final int getOffset() {
		return state.getOffset();
	}

	public final int getLength() {
		return this.state.getLength();
	}

	public final int getId() {
		return this.id;
	}

	public int peer(JHeader header) {
		this.state.peer(header.state);

		return super.peer(header, header.getOffset(), header.getLength());
	}

	public String toString() {
		return "(id=" + getId() + ", offset=" + getOffset() + ", length="
		    + getLength() + ")";
	}

	public final JPacket getPacket() {
		return this.packet;
	}

	public final void setPacket(JPacket packet) {
		this.packet = packet;
	}
}