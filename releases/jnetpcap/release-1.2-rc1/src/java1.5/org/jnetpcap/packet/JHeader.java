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

/**
 * A base class for all protocol header definitions.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JHeader
    extends JBuffer {

	/**
	 * This class is peered state of a header a native state structure
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
		public State(Type type) {
			super(STRUCT_NAME, type);
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

	/**
	 * Reference to header's native state structure
	 */
	protected final State state;

	/**
	 * A reference to the packet that this header is part of
	 */
	protected JPacket packet;

	private final int id;

	private final String name;

	private final String nicname;

	private final JField[] fields;

	/**
	 * Constructs a header.
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param name
	 *          comprehensive name of the protocol
	 * @param nicname
	 *          a short name for the protocol
	 */
	public JHeader(int id, String name, String nicname) {
		this(id, DEFAULT_FIELDS, name, nicname);
	}

	/**
	 * Constructs a header.
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param name
	 *          comprehensive name of the protocol
	 */
	public JHeader(int id, String name) {
		this(id, name, name);
	}

	/**
	 * Constructs a header and initializes its static fields
	 * 
	 * @param state
	 *          the default header state object being referenced
	 * @param fields
	 *          fields usd by the formatter to reformat the packet for output
	 * @param name
	 *          comprehensive name of the protocol
	 * @param nicname
	 *          a short name for the protocol
	 */
	public JHeader(State state, JField[] fields, String name, String nicname) {
		super(Type.POINTER);

		this.state = state;
		this.fields = fields;
		this.name = name;
		this.nicname = nicname;
		this.id = state.getId();
		super.order(ByteOrder.nativeOrder());
	}

	/**
	 * Constructs a header and initializes its static fields
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param fields
	 *          fields usd by the formatter to reformat the packet for output
	 * @param name
	 *          comprehensive name of the protocol
	 * @param nicname
	 *          a short name for the protocol
	 */
	public JHeader(int id, JField[] fields, String name, String nicname) {
		super(Type.POINTER);
		this.fields = fields;

		this.id = id;
		this.name = name;
		this.nicname = nicname;
		this.state = new State(Type.POINTER);
		super.order(ByteOrder.nativeOrder());

	}

	/**
	 * Constructs a header and initializes its static fields
	 * 
	 * @param id
	 *          numerical ID of the protocol
	 * @param fields
	 *          fields usd by the formatter to reformat the packet for output
	 * @param name
	 *          comprehensive name of the protocol
	 */
	public JHeader(int id, JField[] fields, String name) {
		this(id, fields, name, name);
	}

	/**
	 * Method that gets called everytime a header is successfully peered with new
	 * buffer and/or state structure. This method in JHeader is empty and is
	 * expected to be overriden by subclasses of JHeader that require special
	 * processing of the header such as decoding its structure at runtime when the
	 * header object is bound to new state.
	 */
	public void decode() {
		// Empty - subclasses can override
	}

	/**
	 * Gets the reference to the current header's native state structure
	 * 
	 * @return current state of the header
	 */
	public State getState() {
		return state;
	}

	/**
	 * Offset into the packet buffer
	 * 
	 * @return offset into the buffer in bytes
	 */
	public final int getOffset() {
		return state.getOffset();
	}

	/**
	 * Length of this header within the buffer
	 * 
	 * @return length in bytes
	 */
	public final int getLength() {
		return this.state.getLength();
	}

	/**
	 * Gets the numerical ID of this protocol header at runtime as assigned by the
	 * JRegistry
	 * 
	 * @return unique numerical ID of this header
	 */
	public final int getId() {
		return this.id;
	}

	/**
	 * Peers, associates a native packet buffer and scanner structure with this
	 * header. This header is unchanged while the header being passed in is
	 * rereferenced to point at this headers buffer and state structure.
	 * 
	 * @param header
	 *          the header to peer with this header
	 * @return number of bytes total that were peered with the supplied header
	 */
	public int peer(JHeader header) {
		this.state.peer(header.state);

		return super.peer(header, header.getOffset(), header.getLength());
	}

	/**
	 * Gets a string with summary information about the header.
	 * 
	 * @return String with summary of the header
	 */
	public String toString() {
		return "(id=" + getId() + ", offset=" + getOffset() + ", length="
		    + getLength() + ")";
	}

	/**
	 * Gets the packet that this header is associated with
	 * 
	 * @return parent packet
	 */
	public final JPacket getPacket() {
		return this.packet;
	}

	/**
	 * Sets the packet that this header should be associated with
	 * 
	 * @param packet
	 *          packet to associate with this header
	 */
	public final void setPacket(JPacket packet) {
		this.packet = packet;
	}

	/**
	 * Retrieves the fields at runtime, that this header has so that they may be
	 * used by a formatter
	 * 
	 * @return an array of fields that this header is made up of, as determined at
	 *         runtime
	 */
	public JField[] getFields() {
		return this.fields;
	}

	/**
	 * Gets the comprehensive name for this header
	 * 
	 * @return the name full name of this header
	 */
	public final String getName() {
		return this.name;
	}

	/**
	 * Gets the short name for this header
	 * 
	 * @return the nicname for this header
	 */
	public final String getNicname() {
		return this.nicname;
	}

}