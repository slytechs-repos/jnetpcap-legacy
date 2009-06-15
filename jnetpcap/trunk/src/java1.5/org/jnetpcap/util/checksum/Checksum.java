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
package org.jnetpcap.util.checksum;

import org.jnetpcap.nio.JBuffer;

/**
 * Main base and utility class that provides native methods for calculating
 * various CRC on buffers.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Checksum {

	/**
	 * A static read-only buffer that is filled with ZEROs. This buffer is usefull
	 * if you need to perform a calculation that requires a certain amount of data
	 * to be zeroed out. This is common when computing CRC on packet headers that
	 * require the header field that stores the CRC value, to be zeroed out for
	 * the computation on itself.
	 */
	public final static JBuffer ZERO_BUFFER = new JBuffer(new byte[256]);

	/**
	 * Calculate CCITT CRC16 checksum using a CRC32 CCITT seed.
	 * 
	 * @param buffer
	 *          buffer to calculate crc on
	 * @param offset
	 *          offset into the buffer
	 * @param length
	 *          length within the buffer
	 * @return calculated crc
	 */
	public static native int crc16CCITT(JBuffer buffer, int offset, int length);

	/**
	 * Calculate CCITT 16-bit checksum using a custom seed.
	 * 
	 * @param buffer
	 *          buffer to calculate crc on
	 * @param offset
	 *          offset into the buffer
	 * @param length
	 *          length within the buffer
	 * @param seed
	 *          starting seed
	 * @return calculated crc
	 */
	public static native int crc16CCITTSeed(
	    JBuffer buffer,
	    int offset,
	    int length,
	    int seed);

	/**
	 * Calculate CCITT 16-bit checksum using a partially calculated CRC16.
	 * 
	 * @param buffer
	 *          buffer to calculate crc on
	 * @param offset
	 *          offset into the buffer
	 * @param length
	 *          length within the buffer
	 * @param crc
	 *          the preload value for the CRC16 computation
	 * @return calculated crc
	 */
	public static int crc16CCITTContinue(
	    JBuffer buffer,
	    int offset,
	    int length,
	    int crc) {
		return crc16CCITTSeed(buffer, offset, length, ~crc);
	}

	/**
	 * Calculate CCITT CRC16 X.25 checksum using a CCITT seed.
	 * 
	 * @param buffer
	 *          buffer to calculate crc on
	 * @param offset
	 *          offset into the buffer
	 * @param length
	 *          length within the buffer
	 * @return calculated crc
	 */
	public static native int crc16X25CCITT(JBuffer buffer, int offset, int length);

	/**
	 * Calculate CCITT CRC32 checksum using a CRC32 CCITT seed.
	 * 
	 * @param buffer
	 *          buffer to calculate crc on
	 * @param offset
	 *          offset into the buffer
	 * @param length
	 *          length within the buffer
	 * @return calculated crc
	 */
	public static native int crc32CCITT(JBuffer buffer, int offset, int length);

	/**
	 * Calculate CCITT CRC32 checksum using a custom seed.
	 * 
	 * @param buffer
	 *          buffer to calculate crc on
	 * @param offset
	 *          offset into the buffer
	 * @param length
	 *          length within the buffer
	 * @param seed
	 *          starting seed
	 * @return calculated crc
	 */
	public static native int crc32CCITTSeed(
	    JBuffer buffer,
	    int offset,
	    int length,
	    int seed);

	/**
	 * Calculate a standard CRC32C checksum using a custom seed.
	 * 
	 * @param buffer
	 *          buffer to calculate crc on
	 * @param offset
	 *          offset into the buffer
	 * @param length
	 *          length within the buffer
	 * @param crc
	 *          the preload value for the CRC32C computation
	 * @return calculated crc
	 */
	public static native int crc32c(
	    JBuffer buffer,
	    int offset,
	    int length,
	    int crc);

	/**
	 * Calculate a standard CRC32C checksum using a partially calculated CRC32.
	 * 
	 * @param buffer
	 *          buffer to calculate crc on
	 * @param offset
	 *          offset into the buffer
	 * @param length
	 *          length within the buffer
	 * @param crc
	 *          the preload value for the CRC32 computation
	 * @return calculated crc
	 */
	public static int crc32CCITTContinue(
	    JBuffer buffer,
	    int offset,
	    int length,
	    int crc) {
		return crc32CCITTSeed(buffer, offset, length, ~crc);
	}

	/**
	 * Calculate a CRC16 using one's complement of one's complement algorithm.
	 * This method computes the CRC16 on a single buffer chunk.
	 * 
	 * @param buffer
	 *          buffer to reach the chunk of data
	 * @param offset
	 *          offset into the buffer
	 * @param length
	 *          number of bytes to include in calculation
	 * @return computed CRC16
	 */
	public static native int ip1Chunk(JBuffer buffer, int offset, int length);

	public static native int ip2Chunk(
	    JBuffer buffer,
	    int offset1,
	    int length1,
	    int offset2,
	    int length2);

	public static native int ip3Chunk(
	    JBuffer buffer,
	    int offset1,
	    int length1,
	    int offset2,
	    int length2,
	    int offset3,
	    int length3);

	public static native int pseudoTcp(JBuffer buffer, int ipOffset, int tcpOffset);
	public static native int pseudoUdp(JBuffer buffer, int ipOffset, int udpOffset);
	public static native int icmp(JBuffer buffer, int ipOffset, int icmpOffset);

}
