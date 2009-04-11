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
 * structures. The {@link #addresses} is preallocated for convenience.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapIf {
	
	private PcapIf next;
	
	private String name;
	
	private String description;
	
	private PcapAddr addresses;
	
	private int flags;

	/**
   * @return the next
   */
  public final PcapIf getNext() {
  	return this.next;
  }

	/**
   * @return the name
   */
  public final String getName() {
  	return this.name;
  }

	/**
   * @return the description
   */
  public final String getDescription() {
  	return this.description;
  }

	/**
   * @return the addresses
   */
  public final PcapAddr getAddresses() {
  	return this.addresses;
  }

	/**
   * @return the flags
   */
  public final int getFlags() {
  	return this.flags;
  }
  
  @SuppressWarnings("unchecked")
  public List toList() {
  	
  	/**
  	 * Don't use generics to keep compatiblity pre 1.5
  	 */
  	List list = new ArrayList();
  	
  	PcapIf i = next; // we skip the first one
  	
  	while (i != null) {
  		list.add(i);
  		
  		i = i.next;
  	}
  	
  	return list;
  }
  
  public String toString() {
  	StringBuilder out = new StringBuilder();
  	
  	out.append("[");
  	out.append("flags=").append(flags);
  	if (addresses != null) {
  		out.append(", addresses=").append(addresses.toList());
  	}
//  	out.append(", name=").append(name);
//  	out.append(", desc=").append(description);
  	
  	out.append("]");
  	
//  	if (next != null) {
//  		out.append("\n").append(next.toString());
//  	}
  	
  	return out.toString();
  }

}
