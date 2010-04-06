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
package org.jnetpcap.packet;

/**
 * A jNetPcap callback handler that dispatches multiple captured packets in a
 * single buffer. The callback method is only called when the buffer is full or
 * when the capture process has been iterrupted by either a user call to a
 * method such as <code>Pcap.breakLoop</code> or timeout occured.
 * <p>
 * The handler can be setup using appropriate <code>Pcap.loop</code> or
 * <code>Pcap.dispatch</code> methods.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 * @param <T> user type
 */
public interface JPacketBufferHandler<T> {

	/**
	 * Called when a new buffer is filled and ready for processing.
	 * 
	 * @param buffer
	 *          buffer containing raw packets
	 * @param user
	 *          user supplied object
	 */
	public void nextBuffer(JPacketBuffer buffer, T user);
}
