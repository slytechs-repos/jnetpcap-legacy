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
public interface ByteBufferHandler<T> {

	/**
	 * Callback method that will called by libpcap when a new packet is captured
	 * 
	 * @param header
	 *          pcap capture header
	 * @param buffer
	 *          Buffer containing packet data. The new ByteBuffer object is
	 *          allocated per call for the peering, the data is not copied but
	 *          referenced.
	 * @param user
	 *          user supplied object
	 */
	public void nextPacket(PcapHeader header, ByteBuffer buffer, T user);
}
