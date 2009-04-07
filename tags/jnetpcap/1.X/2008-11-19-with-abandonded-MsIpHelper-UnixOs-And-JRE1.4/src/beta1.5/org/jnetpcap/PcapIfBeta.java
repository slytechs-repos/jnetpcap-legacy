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

import java.io.IOException;

/**
 * Class peered with native <code>pcap_if_t</code> structure. Addresses is
 * replaced as a list to simulate a linked list of address structures. The
 * {@link #addresses} is preallocated for convenience. This is not a JNI peering
 * class, and is only a read-only object.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class PcapIfBeta extends PcapIf {

	/**
	 * Retrieves the hardware address or MAC for the current pcap interface.
	 * <p>
	 * Note that this method is not part of the native libpcap API.
	 * </p>
	 * 
	 * @since 1.2
	 * @return hardware address or null if interface does not support having a
	 *         hardware address
	 * @throws IOException
	 *           any communication errors
	 */
	public final byte[] getHardwareAddress() throws IOException {
		return PcapUtils.getHardwareAddress(this);
	}

}
