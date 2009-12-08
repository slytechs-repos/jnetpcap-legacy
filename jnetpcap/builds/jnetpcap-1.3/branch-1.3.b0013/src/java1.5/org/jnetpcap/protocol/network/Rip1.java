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
package org.jnetpcap.protocol.network;

import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;

/**
 * Routing Information Protocol version 1 (RIP). This class provides access
 * method for reading every field in RIP version 1 protocol. The routing table
 * returned only defines accessor methods for reading version 1 fields.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @See Rip2
 */
public class Rip1
    extends
    Rip {

	/**
	 * Rip1 routing table entry definition.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@Header
	public static class EntryV1
	    extends
	    JSubHeader<Rip1> {

		@Field(offset = 4 * 8, length = 32)
		public byte[] address() {
			return super.getByteArray(4, 4);
		}

		@Field(offset = 0 * 8, length = 16)
		public int family() {
			return super.getUShort(0);
		}

		@Field(offset = 16 * 8, length = 32)
		public int metric() {
			return super.getInt(16);
		}

	}

	private EntryV1[] routingTable;

	/**
	 * The routing table is the only thing that needs decoding. The routing table
	 * is lazy decoded using {@link Rip1#decodeRoutingTable()} which only then
	 * creates routing table entries.
	 */
	@Override
	protected void decodeHeader() {
		super.decodeHeader();
		this.routingTable = null;
	}

	/**
	 * Do the actual decoding of the routing table.
	 */
	private void decodeRoutingTable() {

		this.routingTable = new EntryV1[this.count];

		for (int i = 0; i < this.count; i++) {
			final EntryV1 e = new EntryV1();
			this.routingTable[i] = e;

			e.peer(this, 4 + i * 20, 20);
		}
	}

	/**
	 * Gets the routing table.
	 * 
	 * @return an array of routing table entries
	 */
	@Field(offset = 4 * 8, format = "%RIP")
	public EntryV1[] routingTable() {
		if (this.routingTable == null) {
			decodeRoutingTable();
		}

		return this.routingTable;
	}

	/**
	 * Length of the routing table in bits.
	 * 
	 * @return
	 */
	@Dynamic(Field.Property.LENGTH)
	public int routingTableLength() {
		return this.count * 20 * 8;
	}
}
