/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap.packet;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.DefaultField;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Class JHeader.
 */
public abstract class JHeader
    extends
    JBuffer implements JPayloadAccessor {

	/**
	 * The Class State.
	 */
	public static class State
	    extends
	    JStruct {

		/** The Constant FLAG_CRC_INVALID. */
		public final static int FLAG_CRC_INVALID = 0x0080;

		/** The Constant FLAG_CRC_PERFORMED. */
		public final static int FLAG_CRC_PERFORMED = 0x0040;

		/** The Constant FLAG_GAP_TRUNCATED. */
		public final static int FLAG_GAP_TRUNCATED = 0x0008;

		/** The Constant FLAG_HEADER_TRUNCATED. */
		public final static int FLAG_HEADER_TRUNCATED = 0x0002;

		/** The Constant FLAG_HEURISTIC_BINDING. */
		public final static int FLAG_HEURISTIC_BINDING = 0x0020;

		/** The Constant FLAG_PAYLOAD_TRUNCATED. */
		public final static int FLAG_PAYLOAD_TRUNCATED = 0x0004;

		/** The Constant FLAG_POSTFIX_TRUNCATED. */
		public final static int FLAG_POSTFIX_TRUNCATED = 0x0010;

		/** The Constant FLAG_PREFIX_TRUNCATED. */
		public final static int FLAG_PREFIX_TRUNCATED = 0x0001;

		/** The Constant FLAG_HEADER_FRAGMENTED. */
		public final static int FLAG_HEADER_FRAGMENTED = 0x0100;

		/** The Constant FLAG_FIELDS_DISSECTED. */
		public final static int FLAG_FIELDS_DISSECTED = 0x0200;

		/** The Constant FLAG_SUBHEADERS_DISSECTED. */
		public final static int FLAG_SUBHEADERS_DISSECTED = 0x0400;

		/** The Constant FLAG_IGNORE_BOUNDS. */
		public final static int FLAG_IGNORE_BOUNDS = 0x0800;

		/** The Constant STRUCT_NAME. */
		public final static String STRUCT_NAME = "header_t";

		/**
		 * Instantiates a new state.
		 * 
		 * @param type
		 *          the type
		 */
		public State(Type type) {
			super(STRUCT_NAME, type);
		}

		/**
		 * Gets the flags.
		 * 
		 * @return the flags
		 */
		public native int getFlags();

		/**
		 * Gets the gap.
		 * 
		 * @return the gap
		 */
		public native int getGap();

		/**
		 * Gets the id.
		 * 
		 * @return the id
		 */
		public native int getId();

		/**
		 * Gets the length.
		 * 
		 * @return the length
		 */
		public native int getLength();

		/**
		 * Gets the offset.
		 * 
		 * @return the offset
		 */
		public native int getOffset();

		/**
		 * Gets the payload.
		 * 
		 * @return the payload
		 */
		public native int getPayload();

		/**
		 * Gets the postfix.
		 * 
		 * @return the postfix
		 */
		public native int getPostfix();

		/**
		 * Gets the prefix.
		 * 
		 * @return the prefix
		 */
		public native int getPrefix();

		/**
		 * Checks if is direct.
		 * 
		 * @return true, if is direct
		 */
		public boolean isDirect() {
			return true;
		}

		/**
		 * Peer.
		 * 
		 * @param peer
		 *          the peer
		 * @return the int
		 */
		public int peer(State peer) {
			if (peer.isDirect() == false) {
				throw new IllegalStateException(
				    "DirectState can only peer with another DirectState");
			}
			return super.peer(peer);
		}

		/**
		 * Sets the flags.
		 * 
		 * @param flags
		 *          the new flags
		 */
		public native void setFlags(int flags);

		/* (non-Javadoc)
		 * @see org.jnetpcap.nio.JStruct#toString()
		 */
		public String toString() {
			return "(id=" + getId() + ", offset=" + getOffset() + ", length="
			    + getLength() + ")";
		}
	}

	/** The Constant BYTE. */
	public final static int BYTE = 8;

	/** The Constant DEFAULT_FIELDS. */
	private final static JField[] DEFAULT_FIELDS = new JField[0];

	/** The Constant EMPTY_HEADER_ARRAY. */
	protected final static JHeader[] EMPTY_HEADER_ARRAY = new JHeader[0];

	/**
	 * Sizeof.
	 * 
	 * @return the int
	 */
	public native static int sizeof();

	/** The annotated header. */
	protected AnnotatedHeader annotatedHeader;

	/** The fields. */
	private JField[] fields;

	/** The id. */
	private int id;

	/** The is sub header. */
	protected boolean isSubHeader = false;

	/** The name. */
	private String name;

	/** The nicname. */
	private String nicname;

	/** The packet. */
	protected JPacket packet;

	/** The state. */
	protected final State state;

	/** The index. */
	private int index = -1;

	/**
	 * Instantiates a new j header.
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
	 * Instantiates a new j header.
	 * 
	 * @param id
	 *          the id
	 * @param fields
	 *          the fields
	 * @param name
	 *          the name
	 */
	public JHeader(int id, JField[] fields, String name) {
		this(id, fields, name, name);
	}

	/**
	 * Instantiates a new j header.
	 * 
	 * @param id
	 *          the id
	 * @param fields
	 *          the fields
	 * @param name
	 *          the name
	 * @param nicname
	 *          the nicname
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
	 * Instantiates a new j header.
	 * 
	 * @param id
	 *          the id
	 * @param name
	 *          the name
	 */
	public JHeader(int id, String name) {
		this(id, name, name);
	}

	/**
	 * Instantiates a new j header.
	 * 
	 * @param id
	 *          the id
	 * @param name
	 *          the name
	 * @param nicname
	 *          the nicname
	 */
	public JHeader(int id, String name, String nicname) {
		this(id, DEFAULT_FIELDS, name, nicname);
	}

	/**
	 * Instantiates a new j header.
	 * 
	 * @param protocol
	 *          the protocol
	 */
	public JHeader(JProtocol protocol) {
		super(Type.POINTER);
		order(ByteOrder.BIG_ENDIAN); // network byte order by default
		state = new State(Type.POINTER);

		this.id = protocol.getId();
		AnnotatedHeader header = JRegistry.lookupAnnotatedHeader(protocol);

		initFromAnnotatedHeader(header);
	}

	/**
	 * Instantiates a new j header.
	 * 
	 * @param state
	 *          the state
	 * @param fields
	 *          the fields
	 * @param name
	 *          the name
	 * @param nicname
	 *          the nicname
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
	 * Decode.
	 */
	public final void decode() {
		decodeHeader();
		validateHeader();
	}

	/**
	 * Decode header.
	 */
	protected void decodeHeader() {
		// Empty
	}

	/**
	 * Gets the annotated header.
	 * 
	 * @return the annotated header
	 */
	public AnnotatedHeader getAnnotatedHeader() {
		return this.annotatedHeader;
	}

	/**
	 * Gets the description.
	 * 
	 * @return the description
	 */
	public String getDescription() {
		return annotatedHeader.getDescription();
	}

	/**
	 * Gets the fields.
	 * 
	 * @return the fields
	 */
	public JField[] getFields() {

		JField.sortFieldByOffset(fields, this, true);

		return this.fields;
	}

	/**
	 * Gets the gap.
	 * 
	 * @return the gap
	 */
	public byte[] getGap() {
		return packet.getByteArray(getGapOffset(), getGapLength());
	}

	/**
	 * Gets the gap length.
	 * 
	 * @return the gap length
	 */
	public int getGapLength() {
		return state.getGap();
	}

	/**
	 * Gets the gap offset.
	 * 
	 * @return the gap offset
	 */
	public int getGapOffset() {
		return getOffset() + getHeaderLength();
	}

	/**
	 * Gets the header.
	 * 
	 * @return the header
	 */
	public byte[] getHeader() {
		return packet.getByteArray(getHeaderOffset(), getHeaderLength());
	}

	/**
	 * Gets the header length.
	 * 
	 * @return the header length
	 */
	public int getHeaderLength() {
		return state.getLength();
	}

	/**
	 * Gets the header offset.
	 * 
	 * @return the header offset
	 */
	public int getHeaderOffset() {
		return state.getOffset();
	}

	/**
	 * Gets the id.
	 * 
	 * @return the id
	 */
	public final int getId() {
		return this.id;
	}

	/**
	 * Gets the length.
	 * 
	 * @return the length
	 */
	public int getLength() {
		return this.state.getLength();
	}

	/**
	 * Gets the name.
	 * 
	 * @return the name
	 */
	public final String getName() {
		return this.name;
	}

	/**
	 * Gets the nicname.
	 * 
	 * @return the nicname
	 */
	public final String getNicname() {
		return this.nicname;
	}

	/**
	 * Gets the offset.
	 * 
	 * @return the offset
	 */
	public int getOffset() {
		return state.getOffset();
	}

	/**
	 * Gets the a reference to the packet that this header is part of.
	 * 
	 * @return the a reference to the packet that this header is part of
	 */
	public final JPacket getPacket() {
		return this.packet;
	}

	/**
	 * Gets the parent.
	 * 
	 * @return the parent
	 */
	public JHeader getParent() {
		return this;
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JPayloadAccessor#getPayload()
	 */
	public byte[] getPayload() {
		return packet.getByteArray(getPayloadOffset(), getPayloadLength());
	}

	/**
	 * Gets the payload length.
	 * 
	 * @return the payload length
	 */
	public int getPayloadLength() {
		return state.getPayload();
	}

	/**
	 * Gets the payload offset.
	 * 
	 * @return the payload offset
	 */
	public int getPayloadOffset() {
		return getGapOffset() + getGapLength();
	}

	/**
	 * Gets the postfix.
	 * 
	 * @return the postfix
	 */
	public byte[] getPostfix() {
		return packet.getByteArray(getPostfixOffset(), getPostfixLength());
	}

	/**
	 * Gets the postfix length.
	 * 
	 * @return the postfix length
	 */
	public int getPostfixLength() {
		return state.getPostfix();
	}

	/**
	 * Gets the postfix offset.
	 * 
	 * @return the postfix offset
	 */
	public int getPostfixOffset() {
		return getPayloadOffset() + getPayloadLength();
	}

	/**
	 * Gets the prefix.
	 * 
	 * @return the prefix
	 */
	public byte[] getPrefix() {
		return packet.getByteArray(getPrefixOffset(), getPrefixLength());
	}

	/**
	 * Gets the prefix length.
	 * 
	 * @return the prefix length
	 */
	public int getPrefixLength() {
		return state.getPrefix();
	}

	/**
	 * Gets the prefix offset.
	 * 
	 * @return the prefix offset
	 */
	public int getPrefixOffset() {
		return getOffset() - getPrefixLength();
	}

	/**
	 * Gets the reference to header's native state structure.
	 * 
	 * @return the reference to header's native state structure
	 */
	public State getState() {
		return state;
	}

	/**
	 * Gets the sub headers.
	 * 
	 * @return the sub headers
	 */
	public JHeader[] getSubHeaders() {
		return EMPTY_HEADER_ARRAY;
	}

	/**
	 * Checks for description.
	 * 
	 * @return true, if successful
	 */
	public boolean hasDescription() {
		return annotatedHeader.getDescription() != null;
	}

	/**
	 * Checks for gap.
	 * 
	 * @return true, if successful
	 */
	public boolean hasGap() {
		return getGapLength() != 0;
	}

	/**
	 * Checks for payload.
	 * 
	 * @return true, if successful
	 */
	public boolean hasPayload() {
		return getPayloadLength() != 0;
	}

	/**
	 * Checks for postfix.
	 * 
	 * @return true, if successful
	 */
	public boolean hasPostfix() {
		return getPostfixLength() != 0;
	}

	/**
	 * Checks for prefix.
	 * 
	 * @return true, if successful
	 */
	public boolean hasPrefix() {
		return getPrefixLength() != 0;
	}

	/**
	 * Checks for sub headers.
	 * 
	 * @return true, if successful
	 */
	public boolean hasSubHeaders() {
		return false;
	}

	/**
	 * Inits the from annotated header.
	 * 
	 * @param header
	 *          the header
	 */
	private void initFromAnnotatedHeader(AnnotatedHeader header) {
		this.annotatedHeader = header;

		this.name = header.getName();
		this.nicname = header.getNicname();

		this.fields = DefaultField.fromAnnotatedFields(header.getFields());
	}

	/**
	 * Checks if is gap truncated.
	 * 
	 * @return true, if is gap truncated
	 */
	public boolean isGapTruncated() {
		return (state.getFlags() & State.FLAG_GAP_TRUNCATED) != 0;
	}

	/**
	 * Checks if is header truncated.
	 * 
	 * @return true, if is header truncated
	 */
	public boolean isHeaderTruncated() {
		return (state.getFlags() & State.FLAG_HEADER_TRUNCATED) != 0;
	}

	/**
	 * Checks if is payload truncated.
	 * 
	 * @return true, if is payload truncated
	 */
	public boolean isPayloadTruncated() {
		return (state.getFlags() & State.FLAG_PAYLOAD_TRUNCATED) != 0;
	}

	/**
	 * Checks if is postfix truncated.
	 * 
	 * @return true, if is postfix truncated
	 */
	public boolean isPostfixTruncated() {
		return (state.getFlags() & State.FLAG_POSTFIX_TRUNCATED) != 0;
	}

	/**
	 * Checks if is prefix truncated.
	 * 
	 * @return true, if is prefix truncated
	 */
	public boolean isPrefixTruncated() {
		return (state.getFlags() & State.FLAG_PREFIX_TRUNCATED) != 0;
	}

	/**
	 * Peer.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int peer(JBuffer buffer, int offset) {
		// int length = this.lengthMethod.getHeaderLength(buffer, offset);
		//
		// return peer(buffer, offset, length);

		return 0;
	}

	/**
	 * Peer.
	 * 
	 * @param header
	 *          the header
	 * @return the int
	 */
	public int peer(JHeader header) {
		this.state.peer(header.state);

		return super.peer(header, header.getOffset(), header.getLength());
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JPayloadAccessor#peerPayloadTo(org.jnetpcap.nio.JBuffer)
	 */
	public JBuffer peerPayloadTo(JBuffer buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		buffer.peer(packet, offset, packet.remaining(offset));

		return buffer;
	}

	/**
	 * Sets the a reference to the packet that this header is part of.
	 * 
	 * @param packet
	 *          the new a reference to the packet that this header is part of
	 */
	public final void setPacket(JPacket packet) {
		this.packet = packet;
	}

	/**
	 * Sets the sub headers.
	 * 
	 * @param headers
	 *          the new sub headers
	 */
	public void setSubHeaders(JHeader[] headers) {
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
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

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JPayloadAccessor#transferPayloadTo(byte[])
	 */
	public byte[] transferPayloadTo(byte[] buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		return packet.getByteArray(offset, buffer);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JPayloadAccessor#transferPayloadTo(java.nio.ByteBuffer)
	 */
	public ByteBuffer transferPayloadTo(ByteBuffer buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		packet.transferTo(buffer, offset, packet.remaining(offset));

		return buffer;
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.packet.JPayloadAccessor#transferPayloadTo(org.jnetpcap.nio.JBuffer)
	 */
	public JBuffer transferPayloadTo(JBuffer buffer) {
		final JPacket packet = getPacket();
		final int offset = getOffset() + size();

		packet.transferTo(buffer, offset, packet.remaining(offset), 0);

		return buffer;
	}

	/**
	 * Sets the index.
	 * 
	 * @param index
	 *          the new index
	 */
	void setIndex(int index) {
		this.index = index;
	}

	/**
	 * Gets the index.
	 * 
	 * @return the index
	 */
	public int getIndex() {
		return this.index;
	}

	/**
	 * Validate header.
	 */
	protected void validateHeader() {

	}

	/**
	 * Checks for next header.
	 * 
	 * @return true, if successful
	 */
	public boolean hasNextHeader() {
		return this.index + 1 < packet.getState().getHeaderCount();
	}

	/**
	 * Gets the next header id.
	 * 
	 * @return the next header id
	 */
	public int getNextHeaderId() {
		return packet.getState().getHeaderIdByIndex(index + 1);
	}

	/**
	 * Gets the next header offset.
	 * 
	 * @return the next header offset
	 */
	public int getNextHeaderOffset() {
		return packet.getState().getHeaderOffsetByIndex(index + 1);
	}

	/**
	 * Checks for previous header.
	 * 
	 * @return true, if successful
	 */
	public boolean hasPreviousHeader() {
		return this.index > 0;
	}

	/**
	 * Gets the previous header id.
	 * 
	 * @return the previous header id
	 */
	public int getPreviousHeaderId() {
		return packet.getState().getHeaderIdByIndex(index - 1);
	}

	/**
	 * Gets the previous header offset.
	 * 
	 * @return the previous header offset
	 */
	public int getPreviousHeaderOffset() {
		return packet.getState().getHeaderOffsetByIndex(index - 1);
	}

	/**
	 * Checks if is fragmented.
	 * 
	 * @return true, if is fragmented
	 */
	public boolean isFragmented() {
		return ((getState().getFlags() & JHeader.State.FLAG_HEADER_FRAGMENTED) > 0);
	}

}
