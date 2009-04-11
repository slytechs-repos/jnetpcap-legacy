/**
 * $Id$
 * Copyright (C) 2006 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jnetpcap;

/**
 * Structure that keeps statistical values on an interface.
 * 
 * @author Mark Bednarczyk
 */
public interface PcapStatistics {

	/**
	 * Number of packets transited on the network.
	 * 
	 * @return
	 *   number of packets transited on the network.
	 */
	public long getReceived();
	
	/**
	 * Number of packets dropped by the driver.
	 * 
	 * @return
	 *   number of packets dropped by the driver.
	 */
	public long getDropped();
	
	/**
	 * Drops by interface, not yet supported.
	 * @return
	 *   drops by interface, not yet supported
	 */
	public long getIfDrops();
	
	/**
	 * Number of packets captured, i.e number of packets that 
	 * are accepted by the filter, that find place in the kernel buffer and 
	 * therefore that actually reach the application. For backward compatibility, 
	 * pcap_stats() does not fill this member, so use pcap_stats_ex() to get it.
	 * 
	 * Win32 specific. 
	 * 
	 * @return
	 *   Number of packets captured
	 */
	public long getPacketCaptureCount();
}
