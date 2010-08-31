/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.protocol.lan;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.ProtocolSuite;
import org.jnetpcap.packet.annotate.Header.Layer;
import org.jnetpcap.protocol.JProtocol;

/**
 * <p>
 * Spanning-Tree Protocol (STP) as defined in the IEEE 802.1D is a link
 * management protocol that provides path redundancy while preventing
 * undesirable loops in the network. For an Ethernet network to function
 * properly, only one active path can exist between two stations. Loops occur in
 * networks for a variety of reasons. The most common reason you find loops in
 * networks is the result of a deliberate attempt to provide redundancy - in
 * case one link or switch fails, another link or switch can take over.
 * </p>
 * <p>
 * STP is a technology that allows bridges to communicate with each other to
 * discover physical loops in the network. The protocol then specifies an
 * algorithm that bridges can use to create a loop-free logical topology. In
 * other words, STP creates a tree structure of loop-free leaves and branches
 * that spans the entire Layer 2 network.
 * </p>
 * <p>
 * Spanning-Tree Protocol operation is transparent to end stations, which are
 * unaware whether they are connected to a single LAN segment or a switched LAN
 * of multiple segments. Where two bridges are used to interconnect the same two
 * computer network segments, spanning tree is a protocol that allows the
 * bridges to exchange information so that only one of them will handle a given
 * message that is being sent between two computers within the network.
 * </p>
 * <p>
 * Bridge Protocol Data Units (BPDUs) is used by bridges in a network to
 * exchange information regarding their status. The Spanning-Tree Protocol uses
 * the BPDU information to elect the root switch and root port for the switched
 * network, as well as the root port and designated port for each switched
 * segment.
 * </p>
 * <p>
 * The program in each bridge that allows it to determine how to use the
 * protocol is known as the spanning tree algorithm, which is specifically
 * constructed to avoid bridge loops. The algorithm is responsible for a bridge
 * using only the most efficient path when faced with multiple paths. If the
 * best path fails, the algorithm recalculates the network and finds the next
 * best route.
 * </p>
 * <p>
 * The spanning tree algorithm determines the network (which computer hosts are
 * in which segment) and this data is exchanged using Bridge Protocol Data Units
 * (BPDUs). It is broken down into two steps:
 * </p>
 * <p>
 * Step 1: The algorithm determines the best message a bridge can send by
 * evaluating the configuration messages it has received and choosing the best
 * option.
 * </p>
 * <p>
 * Step 2: Once it selects the top message for a particular bridge to send, it
 * compares its choice with possible configuration messages from the
 * non-root-connections it has. If the best option from step 1 isn't better than
 * what it receives from the non-root-connections, it will prune that port.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header(length = 35, nicname = "STP", description = "Spanning Tree Protocol", osi = Layer.DATALINK, suite = ProtocolSuite.LAN, name = "BPDU")
public class IEEE802dot1d
    extends
    JHeader {

	/**
	 * Various possible flags for this message
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Flags {

		/**
		 * Topology change notification
		 */
		NOTIFICATION,

		/**
		 * This message is an acknowledgment message
		 */
		ACK,

		/**
		 * Topology has not changed
		 */
		NO_CHANGE,

		/**
		 * Topology has changed
		 */
		CHANGE
	}

	/**
	 * BPDU message type
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Type {
		/**
		 * Configuration message
		 */
		CONFIG,

		/**
		 * Topology change notification
		 */
		CHANGE
	}

	/**
	 * Numerical ID for this core protocol
	 */
	public final static int ID = JProtocol.IEEE_802DOT2D_ID;

	/**
	 * Get protocol ID. Always 0
	 * 
	 * @return 0
	 */
	@Field(offset = 0 * BYTE, length = 2 * BYTE)
	public int id() {
		return super.getUShort(0);
	}

	/**
	 * Set protocol ID. Should be always set to 0.
	 * 
	 * @param value
	 *          should be 0
	 */
	public void id(int value) {
		super.setUByte(0, value);
	}

	/**
	 * Gets the protocol version.
	 * 
	 * @return version of this STP protocol
	 */
	@Field(offset = 2 * BYTE, length = 1 * BYTE)
	public int version() {
		return super.getUByte(2);
	}

	/**
	 * Sets the version of this protocol.
	 * 
	 * @param value
	 *          version of protocol
	 */
	public void version(int value) {
		super.setUByte(2, value);
	}

	/**
	 * Gets the type of message this is.
	 * 
	 * @return Value of 0 means its a configuration message. A value of 0xE0000
	 *         means its a topology change notification.
	 */
	@Field(offset = 3 * BYTE, length = 1 * BYTE)
	public int type() {
		return super.getUByte(3);
	}

	/**
	 * Returns an enum contant which represents the message type
	 * 
	 * @return message type
	 */
	public IEEE802dot1d.Type typeEnum() {
		switch (type()) {
			case 0:
				return IEEE802dot1d.Type.CONFIG;

			case (1 << 7):
				return IEEE802dot1d.Type.CHANGE;

			default:
				return null;
		}
	}

	/**
	 * Sets the message type by enum constant
	 * 
	 * @param type
	 *          message type constant
	 */
	public void typeEnum(IEEE802dot1d.Type type) {
		switch (type) {
			case CONFIG:
				type(0);
				break;

			case CHANGE:
				type(1 << 7);
				break;

			default:
				throw new IllegalStateException("unknown STP message type");
		}
	}

	/**
	 * Sets the type value for this message.
	 * 
	 * @param value
	 *          message type
	 */
	public void type(int value) {
		super.setUByte(3, value);
	}

	/**
	 * BPDU flags
	 * 
	 * @return flags for this message
	 */
	@Field(offset = 4 * BYTE, length = 1 * BYTE)
	public int flags() {
		return super.getUByte(4);
	}

	public void flags(int value) {
		super.setUByte(4, value);
	}

	@Field(parent = "flags", offset = 0, length = 1)
	public int flags_ack() {
		return flags() & 0x1;
	}

	public void flags_ack(int value) {
		flags(flags() & ~(0x1) | (value & 0x1));
	}

	public Flags flags_ackEnum() {
		return (flags_ack() == 1) ? Flags.ACK : Flags.NOTIFICATION;
	}

	@Field(parent = "flags", offset = 1, length = 6)
	public int flags_reserved() {
		return flags() & 0xe6;
	}

	@Field(parent = "flags", offset = 7, length = 1)
	public int flags_change() {
		return flags() & (1 << 7);
	}

	public Flags flags_changeEnum() {
		return (flags_change() == 1) ? Flags.CHANGE : Flags.NO_CHANGE;
	}

	@Field(offset = 5 * BYTE, length = 8 * BYTE, format = "#mac#")
	public byte[] rootId() {
		return super.getByteArray(5, 8);
	}

	@Field(offset = 13 * BYTE, length = 4 * BYTE)
	public long rootCost() {
		return super.getUInt(13);
	}

	@Field(offset = 18 * BYTE, length = 8 * BYTE, format = "#mac#")
	public byte[] bridgeId() {
		return super.getByteArray(17, 8);
	}

	@Field(offset = 25 * BYTE, length = 2 * BYTE, format = "%x")
	public int port() {
		return super.getUShort(25);
	}

	@Field(offset = 27 * BYTE, length = 2 * BYTE)
	public int age() {
		return super.getUShort(27);
	}

	@Field(offset = 29 * BYTE, length = 2 * BYTE)
	public int maxAge() {
		return super.getUShort(29);
	}

	@Field(offset = 31 * BYTE, length = 2 * BYTE)
	public int helloTime() {
		return super.getUShort(31);
	}

	@Field(offset = 33 * BYTE, length = 2 * BYTE)
	public int forwardDelay() {
		return super.getUShort(33);
	}
	
	@Dynamic(Field.Property.DESCRIPTION)
	public String maxAgeDescription() {
		return "" + (maxAge() / 256) + " seconds";
	}
	
	@Dynamic(Field.Property.DESCRIPTION)
	public String helloTimeDescription() {
		return "" + (helloTime() / 256) + " seconds";
	}
	
	@Dynamic(Field.Property.DESCRIPTION)
	public String forwardDelayDescription() {
		return "" + (forwardDelay() / 256) + " seconds";
	}

}
