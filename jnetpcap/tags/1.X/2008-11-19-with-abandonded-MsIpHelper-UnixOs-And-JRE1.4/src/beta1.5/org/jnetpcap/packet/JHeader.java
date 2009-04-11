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
import org.jnetpcap.packet.format.JDynamicField;
import org.jnetpcap.packet.format.JField;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

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

	/**
	 * Default field object for JFormatter that does a hex dump on the entire
	 * header
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] DEFAULT_FIELDS =
	    { new JField(Style.BYTE_ARRAY_HEX_DUMP, Priority.LOW, "data", "data",
	        new JDynamicField<JHeader, byte[]>(0) {

		        /*
						 * (non-Javadoc)
						 * 
						 * @see org.jnetpcap.packet.format.JDynamicField#hasField(org.jnetpcap.packet.JHeader)
						 */
		        @Override
		        public boolean hasField(JHeader header) {
		        	setLength(header.getLength());
		        	setOffset(header.getOffset());
		        	
			        return header.getLength() != 0;
		        }

		        public byte[] value(JHeader header) {
			        return header.getByteArray(0, header.getLength());
		        }
	        }), };

	protected final State state;

	protected JPacket packet;

	private final int id;

	private final String name;

	private final String nicname;

	private final JField[] fields;

	public JHeader(int id, String name, String nicname) {
		this(id, DEFAULT_FIELDS, name, nicname);
	}

	public JHeader(int id, String name) {
		this(id, name, name);
	}

	public JHeader(State state, JField[] fields, String name, String nicname) {
		this.state = state;
		this.fields = fields;
		this.name = name;
		this.nicname = nicname;
		this.id = state.getId();
		super.order(ByteOrder.nativeOrder());
	}

	public JHeader(int id, JField[] fields, String name, String nicname) {
		this.fields = fields;

		this.id = id;
		this.name = name;
		this.nicname = nicname;
		this.state = new State();
		super.order(ByteOrder.nativeOrder());

	}

	/**
	 * @param id2
	 * @param fields2
	 * @param string
	 */
	public JHeader(int id, JField[] fields, String name) {
		this(id, fields, name, name);
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

	public JField[] getFields() {
		return this.fields;
	}

	/**
	 * @return the name
	 */
	public final String getName() {
		return this.name;
	}

	/**
	 * @return the nicname
	 */
	public final String getNicname() {
		return this.nicname;
	}

}