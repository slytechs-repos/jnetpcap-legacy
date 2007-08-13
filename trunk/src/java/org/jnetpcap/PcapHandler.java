/**
 * $Id$ Copyright (C) 2006 Sly Technologies, Inc. This library is free software;
 * you can redistribute it and/or modify it under the terms of the GNU Lesser
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

import java.nio.ByteBuffer;

/**
 * A handler, listener or call back inteface that gets notified when a new
 * packet has been captured.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @param <T>
 *          user object type
 */
public interface PcapHandler<T> {

	/**
	 * Method gets called when a packet is available as dispatched by Libpcap
	 * dispatch or loop calls. The typical <code>struct pcap_pkthdr</code>
	 * structure is decoded in JNI and passed in as java primitives. The supplied
	 * buffer contains the captured packet data. The buffer is initialized as
	 * follows. The position property is set to the start of the packet data and
	 * limit is set to 1 byte passed the end of the packet. The difference between
	 * limit and position properties will equal exactly <code>caplen</code>.
	 * The buffer is reused for each packet. Libpcap is initialized with a custom
	 * capture buffer that backs the ByteBuffer, only is position and limit
	 * properties are adjusted. The buffer may wrap around and start from the
	 * start as determined by libpcap itself. Also the buffer is read-only and the
	 * data is not mutable. Packet data is not copied into the buffer, but written
	 * to directly by the kernel. This ensures that data is only written once into
	 * the buffer and then returned to java envioronment.
	 * 
	 * @param user
	 *          user supplied object to dispatch or loop calls
	 * @param seconds
	 *          timestamp
	 * @param useconds
	 *          timestamp
	 * @param caplen
	 *          amount of data captured
	 * @param len
	 *          original packet length as seen on the network
	 * @param buffer
	 *          buffer containing the packet data.
	 */
	public void nextPacket(T user, long seconds, int useconds, int caplen,
	    int len, ByteBuffer buffer);
}
