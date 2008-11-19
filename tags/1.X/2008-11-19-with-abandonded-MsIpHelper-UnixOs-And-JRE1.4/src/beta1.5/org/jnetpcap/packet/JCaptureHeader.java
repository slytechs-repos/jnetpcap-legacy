/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
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
 * Interface to to capture header provided by the capturing library. For example
 * <code>PcapHeader</code>, the capture header provided by libpcap,
 * implements this interface which provides access to minimum set of information
 * about the capture packet.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JCaptureHeader {

	/**
	 * Retrieves the length of the packet that was actually captured. This could
	 * be only a portion of the original packet if snaplen filter was set during
	 * Pcap.openXXX call. If the packet was not trucated, this length should equal
	 * the length returned by {@link #getFullLength()}.
	 * 
	 * @return length in bytes
	 */
	public int truncatedLength();

	/**
	 * Retrieves the length of the packet before any of it was truncated by the
	 * capture mechanism. This is the size of the orignal packet as it was send
	 * accross the network.
	 * 
	 * @return length in bytes
	 */
	public int fullLength();

	/**
	 * Capture timestamp in UNIX seconds
	 * 
	 * @return timestamp in seconds since 1970
	 */
	public long seconds();

	/**
	 * Fractional part of the second when the packet was captured. If the
	 * resolution of the original capture timestamp is lower than nano seconds,
	 * they are converted to nano seconds. For example of the capture timestamp is
	 * in micro seconds, then the micro seconds fraction is multiplied by a 1000
	 * before being returned to conform to nano second return timestamp.
	 * 
	 * @return Number of nano seconds at the time of the packet capture. The valid
	 *         value returned by this method is from 0 to 999,999,999.
	 */
	public long nanos();
}
