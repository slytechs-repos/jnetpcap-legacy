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
package org.jnetpcap.protocol.network;

import org.jnetpcap.packet.annotate.Field;

// TODO: Auto-generated Javadoc
/**
 * The Class Rip2.
 */
public abstract class Rip2
    extends
    Rip1 {

	/** The routing table. */
	private EntryV2[] routingTable;

	/* (non-Javadoc)
	 * @see org.jnetpcap.protocol.network.Rip1#routingTable()
	 */
	@Field(offset = 4 * 8)
	public EntryV2[] routingTable() {
		if (this.routingTable == null) {
			decodeRoutingTable();
		}

		return this.routingTable;
	}

	/**
	 * Decode routing table.
	 */
	private void decodeRoutingTable() {

		this.routingTable = new EntryV2[count];

		for (int i = 0; i < count; i++) {
			final EntryV2 e = new EntryV2();
			this.routingTable[i] = e;

			e.peer(this, 4 + i * 20, 20);
		}
	}

	/**
	 * The Class EntryV2.
	 */
	public static class EntryV2
	    extends
	    EntryV1 {

		/**
		 * Tag.
		 * 
		 * @return the int
		 */
		@Field(offset = 2 * 8, length = 16)
		public int tag() {
			return super.getUShort(2);
		}

		/**
		 * Subnet.
		 * 
		 * @return the byte[]
		 */
		@Field(offset = 8 * 8, length = 32)
		public byte[] subnet() {
			return super.getByteArray(8, 4);
		}

		/**
		 * Next hop.
		 * 
		 * @return the byte[]
		 */
		@Field(offset = 12 * 8, length = 32)
		public byte[] nextHop() {
			return super.getByteArray(12, 4);
		}
	}
}
