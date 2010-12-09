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

import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;

// TODO: Auto-generated Javadoc
/**
 * The Class Rip1.
 */
public class Rip1
    extends
    Rip {

	/**
	 * The Class EntryV1.
	 */
	@Header
	public static class EntryV1
	    extends
	    JSubHeader<Rip1> {

		/**
		 * Address.
		 * 
		 * @return the byte[]
		 */
		@Field(offset = 4 * 8, length = 32)
		public byte[] address() {
			return super.getByteArray(4, 4);
		}

		/**
		 * Family.
		 * 
		 * @return the int
		 */
		@Field(offset = 0 * 8, length = 16)
		public int family() {
			return super.getUShort(0);
		}

		/**
		 * Metric.
		 * 
		 * @return the int
		 */
		@Field(offset = 16 * 8, length = 32)
		public int metric() {
			return super.getInt(16);
		}

	}

	/** The routing table. */
	private EntryV1[] routingTable;

	/* (non-Javadoc)
	 * @see org.jnetpcap.protocol.network.Rip#decodeHeader()
	 */
	@Override
	protected void decodeHeader() {
		super.decodeHeader();
		this.routingTable = null;
	}

	/**
	 * Decode routing table.
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
	 * Routing table.
	 * 
	 * @return the entry v1[]
	 */
	@Field(offset = 4 * 8, format = "%RIP")
	public EntryV1[] routingTable() {
		if (this.routingTable == null) {
			decodeRoutingTable();
		}

		return this.routingTable;
	}

	/**
	 * Routing table length.
	 * 
	 * @return the int
	 */
	@Dynamic(Field.Property.LENGTH)
	public int routingTableLength() {
		return this.count * 20 * 8;
	}
}
