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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.packet.analysis.AnalysisUtils;
import org.jnetpcap.packet.analysis.JAnalysis;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.DefaultField;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;

/**
 * A base class for all protocol header definitions.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JHeader
    extends
    JBuffer implements JPayloadAccessor {

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
	    extends
	    JStruct {

		public final static String STRUCT_NAME = "header_t";

		/**
		 * Create an uninitialized type
		 * 
		 * @param type
		 *          type of memory
		 */
		public State(Type type) {
			super(STRUCT_NAME, type);
		}

		/**
		 * Retrieves the analysis object that is attached to this header.
		 * 
		 * @return an attached analysis based object or null if not set
		 */
		public native JAnalysis getAnalysis();

		public native int getId();

		public native int getLength();

		public native int getOffset();

		public boolean isDirect() {
			return true;
		}

		public int peer(State peer) {
			if (peer.isDirect() == false) {
				throw new IllegalStateException(
				    "DirectState can only peer with another DirectState");
			}
			return super.peer(peer);
		}

		/**
		 * Sets the analysis object for this header.
		 * 
		 * @param state
		 *          packet's state object
		 * @param analysis
		 *          analysis object to set
		 */
		public native void setAnalysis(JPacket.State state, JAnalysis analysis);

		public String toString() {
			return "(id=" + getId() + ", offset=" + getOffset() + ", length="
			    + getLength() + ")";
		}
	}

	/**
	 * No fields
	 */
	private final static JField[] DEFAULT_FIELDS = new JField[0];

	protected final static JHeader[] EMPTY_HEADER_ARRAY = new JHeader[0];

	/**
	 * Gets the size of the native header_t structure on this particular platform
	 * 
	 * @return length in bytes
	 */
	public native static int sizeof();

	protected AnnotatedHeader annotatedHeader;

	private JField[] fields;

	private int id;

	protected boolean isSubHeader = false;

	private String name;

	private String nicname;

	/**
	 * A reference to the packet that this header is part of
	 */
	protected JPacket packet;

	/**
	 * Reference to header's native state structure
	 */
	protected final State state;

	/**
	 * Calls on the header defintion's static annotated \@HeaderLength method to
	 * get header's length. The method is given a buffer and offset as the start
	 * of the header. The method invoked must be defined in the header definition
	 * otherwise an exception will be thrown.
	 */
	public JHeader() {
		super(Type.POINTER);
		order(ByteOrder.BIG_ENDIAN); // network byte order by default
		state = new State(Type.POINTER);

		final JProtocol protocol = JProtocol.valueOf(getClass());

		AnnotatedHeader header;
		if (protocol != null) {
			this.id = protocol.getId();
			header = JRegistry.lookupAnnotatedHeader(protocol);

		} else {
			this.id = JRegistry.lookupId(getClass());
			header = JRegistry.lookupAnnotatedHeader(getClass());
		}

		initFromAnnotatedHeader(header);
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

	public JHeader(JProtocol protocol) {
		super(Type.POINTER);
		order(ByteOrder.BIG_ENDIAN); // network byte order by default
		state = new State(Type.POINTER);

		this.id = protocol.getId();
		AnnotatedHeader header = JRegistry.lookupAnnotatedHeader(protocol);

		initFromAnnotatedHeader(header);
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
	 * Method that gets called everytime a header is successfully peered with new
	 * buffer and/or state structure. This method in JHeader is empty and is
	 * expected to be overriden by subclasses of JHeader that require special
	 * processing of the header such as decoding its structure at runtime when the
	 * header object is bound to new state.
	 */
	public final void decode() {
		decodeHeader();
		validateHeader();
	}

	/**
	 * Allows a header to decode its complex fields
	 */
	protected void decodeHeader() {

	}

	public void addAnalysis(JAnalysis analysis) {

		AnalysisUtils.addToRoot(getPacket().getState(), this.state, analysis);
	}

	public <T extends JAnalysis> T getAnalysis(T analysis) {
		JAnalysis a = state.getAnalysis();
		if (a == null) {
			return null;
		}

		if (a.getType() == AnalysisUtils.CONTAINER_TYPE) {
			return getAnalysis(analysis);
		}

		if (a.getType() == analysis.getType()) {
			analysis.peer(a);
			return analysis;

		} else {
			return null;
		}

	}

	/**
	 * @return
	 */
	public AnnotatedHeader getAnnotatedHeader() {
		return this.annotatedHeader;
	}

	/**
	 * @return
	 */
	public String getDescription() {
		return annotatedHeader.getDescription();
	}

	/**
	 * Retrieves the fields at runtime, that this header has so that they may be
	 * used by a formatter
	 * 
	 * @return an array of fields that this header is made up of, as determined at
	 *         runtime
	 */
	public JField[] getFields() {

		JField.sortFieldByOffset(fields, this, true);

		return this.fields;
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
	 * Length of this header within the buffer
	 * 
	 * @return length in bytes
	 */
	public int getLength() {
		return this.state.getLength();
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

	/**
	 * Offset into the packet buffer
	 * 
	 * @return offset into the buffer in bytes
	 */
	public int getOffset() {
		return state.getOffset();
	}

	/**
	 * Gets the packet that this header is associated with
	 * 
	 * @return parent packet
	 */
	public final JPacket getPacket() {
		return this.packet;
	}

	public JHeader getParent() {
		return this;
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
	 * Gets an array of currently defined sub headers
	 * 
	 * @return array of sub headers
	 */
	public JHeader[] getSubHeaders() {
		return EMPTY_HEADER_ARRAY;
	}

	public int getType() {
		return AnalysisUtils.ROOT_TYPE;
	}

	public boolean hasAnalysis(int type) {
		return state.getAnalysis() != null && state.getAnalysis().hasAnalysis(type);
	}

	public boolean hasAnalysis(Class<? extends JAnalysis> analysis) {
		return state.getAnalysis() != null
		    && state.getAnalysis().hasAnalysis(analysis);
	}

	public <T extends JAnalysis> boolean hasAnalysis(T analysis) {
		return (state.getAnalysis() == null) ? false : state.getAnalysis()
		    .hasAnalysis(analysis);
	}

	/**
	 * @return
	 */
	public boolean hasDescription() {
		return annotatedHeader.getDescription() != null;
	}

	public boolean hasSubHeaders() {
		return false;
	}

	private void initFromAnnotatedHeader(AnnotatedHeader header) {
		this.annotatedHeader = header;

		this.name = header.getName();
		this.nicname = header.getNicname();

		this.fields = DefaultField.fromAnnotatedFields(header.getFields());
	}

	public int peer(JBuffer buffer, int offset) {
		// int length = this.lengthMethod.getHeaderLength(buffer, offset);
		//
		// return peer(buffer, offset, length);

		return 0;
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
	 * Sets the packet that this header should be associated with
	 * 
	 * @param packet
	 *          packet to associate with this header
	 */
	public final void setPacket(JPacket packet) {
		this.packet = packet;
	}

	public void setSubHeaders(JHeader[] headers) {
	}

	/**
	 * Gets a string with summary information about the header.
	 * 
	 * @return String with summary of the header
	 */
	public String toString() {
		JFormatter out = JPacket.getFormatter();
		out.reset();
		try {
			out.format(this);
		} catch (IOException e) {
			throw new IllegalStateException("Unexpected StringBuilder IO error");
		}
		return out.toString();
	}

	/**
	 * Allows a header to validate its values
	 */
	protected void validateHeader() {

	}

	/**
	 * @return
	 */
	public Iterable<JAnalysis> getAnalysisIterable() {
		return AnalysisUtils.toIterable(state.getAnalysis());
	}

	/**
	 * Retrieves the playload data portion of the packet right after the current
	 * header.
	 * 
	 * @return newly allocated byte array containing copy of the contents of the
	 *         header's payload from the packet.
	 */
	public byte[] getPayload() {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		return packet.getByteArray(offset, packet.remaining(offset));
	}
	
	public int getPayloadLength() {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		return packet.size() - offset;
	}

	/**
	 * Copies the payload data portion of the packet right after the current
	 * header to user supplied buffer.
	 * 
	 * @param buffer
	 *          buffer where the data will be written to
	 * @return the same buffer that was passed in
	 */
	public byte[] transferPayloadTo(byte[] buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		return packet.getByteArray(offset, buffer);
	}

	/**
	 * Peers, without copy, the user supplied buffer with payload data portion of
	 * the packet right after the current header.
	 * 
	 * @param buffer
	 *          buffer to peer the data with
	 * @return the same buffer that was passed in
	 */
	public JBuffer peerPayloadTo(JBuffer buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		buffer.peer(packet, offset, packet.remaining(offset));

		return buffer;
	}

	/**
	 * Copies into the user supplied buffer, the payload data portion of the
	 * packet right after the current header.
	 * 
	 * @param buffer
	 *          buffer to copy the data to
	 * @return the same buffer that was passed in
	 */
	public JBuffer transferPayloadTo(JBuffer buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		packet.transferTo(buffer, offset, packet.remaining(offset), 0);

		return buffer;
	}

	/**
	 * Copies into the user supplied buffer, the payload data portion of the
	 * packet right after the current header. The copy will start at the current
	 * ByteBuffer position property.
	 * 
	 * @param buffer
	 *          buffer to copy the data to
	 * @return the same buffer that was passed in
	 */
	public ByteBuffer transferPayloadTo(ByteBuffer buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		packet.transferTo(buffer, offset, packet.remaining(offset));

		return buffer;
	}
}
