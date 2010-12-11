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
package org.jnetpcap;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

// TODO: Auto-generated Javadoc
/**
 * The Class PcapIf.
 */
public class PcapIf {

	/**
	 * Inits the i ds.
	 */
	private native static void initIDs();

	static {
		initIDs();

		try {
			Class.forName("org.jnetpcap.PcapAddr");
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException(e);
		}
	}

	/** The next. */
	private volatile PcapIf next;

	/** The name. */
	private volatile String name;

	/** The description. */
	private volatile String description;

	/** The addresses. */
	private List<PcapAddr> addresses = new ArrayList<PcapAddr>(2);

	/** The flags. */
	private volatile int flags;

	/**
	 * Gets the field is initialized to the next object in native linked list, but
	 * is not accessible from java.
	 * 
	 * @return the field is initialized to the next object in native linked list,
	 *         but is not accessible from java
	 */
	private final PcapIf getNext() {
		return this.next;
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
	 * Gets the description.
	 * 
	 * @return the description
	 */
	public final String getDescription() {
		return this.description;
	}

	/**
	 * Gets the preallocate the list.
	 * 
	 * @return the preallocate the list
	 */
	public final List<PcapAddr> getAddresses() {
		return this.addresses;
	}

	/**
	 * Gets the flags.
	 * 
	 * @return the flags
	 */
	public final int getFlags() {
		return this.flags;
	}

	/**
	 * Gets the hardware address.
	 * 
	 * @return the hardware address
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public byte[] getHardwareAddress() throws IOException {
		return PcapUtils.getHardwareAddress(this);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
  public String toString() {
		StringBuilder out = new StringBuilder();

		out.append("<");
		if (addresses != null && addresses.isEmpty() == false) {
			out.append("flags=").append(flags);
			out.append(", addresses=").append(addresses);
			out.append(", ");
		}
		out.append("name=").append(name);
		out.append(", desc=").append(description);

		out.append(">");

		// if (next != null) {
		// out.append("\n").append(next.toString());
		// }

		return out.toString();
	}

}
