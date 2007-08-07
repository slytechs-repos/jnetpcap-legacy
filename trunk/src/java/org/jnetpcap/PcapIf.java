/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap;

import java.util.ArrayList;
import java.util.List;

/**
 * Object mimicking the structure of the Pcap <code>pcap_if_t</code> structure
 * where addresses is replaced as a list to simulate a linked list of address
 * structures. The {@link #addresses} is preallocated for convenience. This is
 * not a JNI peering class, and is only a read-only object.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class PcapIf {

	/**
	 * The field is initialized to the next object in native linked list, but is
	 * not accessible from java.
	 */
	private volatile PcapIf next;

	private volatile String name;

	private volatile String description;

	/**
	 * Preallocate the list. The list will be filled in based on pcap_addr
	 * structure from JNI. The field can be assigned to any kind of list since JNI
	 * does dynamic lookup on the List.add method. We allocate a more efficient
	 * ArrayList with only 2 addresses max for its initial capacity, as its very
	 * rare to have interfaces assigned multiple addresses. The list will resize
	 * incase there are more then 2 automatically.
	 */
	private List<PcapAddr> addresses = new ArrayList<PcapAddr>(2);

	private volatile int flags;

	/**
	 * pcap_if.next field is unimportant since this java API fills in all the
	 * entries into a List. Since the field does exist, though we leave the method
	 * but make it private and not user accessible. This avoid when next is null
	 * issues.
	 * 
	 * @return the next
	 */
	@SuppressWarnings("unused")
	private final PcapIf getNext() {
		return this.next;
	}

	/**
	 * pcap_if.name field.
	 * 
	 * @return the name
	 */
	public final String getName() {
		return this.name;
	}

	/**
	 * pcap_if.description field.
	 * 
	 * @return the description
	 */
	public final String getDescription() {
		return this.description;
	}

	/**
	 * A list of addresses for this field. The native C linked list of
	 * <code>pcap_if</code> structures is turned into a java <code>List</code>
	 * for convenience.
	 * 
	 * @return the addresses
	 */
	public final List<PcapAddr> getAddresses() {
		return this.addresses;
	}

	/**
	 * pcap_if.flags field.
	 * 
	 * @return the flags
	 */
	public final int getFlags() {
		return this.flags;
	}

	/**
	 * Debug string.
	 */
	public String toString() {
		StringBuilder out = new StringBuilder();

		out.append("[");
		out.append("flags=").append(flags);
		if (addresses != null) {
			out.append(", addresses=").append(addresses);
		}
		// out.append(", name=").append(name);
		// out.append(", desc=").append(description);

		out.append("]");

		// if (next != null) {
		// out.append("\n").append(next.toString());
		// }

		return out.toString();
	}

}
