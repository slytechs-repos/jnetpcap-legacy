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
package org.jnetpcap.util.checksum;

import org.jnetpcap.nio.JBuffer;

// TODO: Auto-generated Javadoc
/**
 * The Class Checksum.
 */
public class Checksum {

	/**
	 * Crc16 ccitt.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the int
	 */
	public static native int crc16CCITT(JBuffer buffer, int offset, int length);

	/**
	 * Crc16 ccitt continue.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @param crc
	 *          the crc
	 * @return the int
	 */
	// public final static JBuffer ZERO_BUFFER = new JBuffer(new byte[256]);

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
	public static int crc16CCITTContinue(JBuffer buffer,
			int offset,
			int length,
			int crc) {
		return crc16CCITTSeed(buffer, offset, length, ~crc);
	}

	/**
	 * Crc16 ccitt seed.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @param seed
	 *          the seed
	 * @return the int
	 */
	public static native int crc16CCITTSeed(JBuffer buffer,
			int offset,
			int length,
			int seed);

	/**
	 * Crc16 x25 ccitt.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the int
	 */
	public static native int crc16X25CCITT(JBuffer buffer, int offset, int length);

	/**
	 * Crc32c.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @param crc
	 *          the crc
	 * @return the int
	 */
	public static native int crc32c(JBuffer buffer,
			int offset,
			int length,
			int crc);

	/**
	 * Crc32 ccitt.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the long
	 */
	public static native long crc32CCITT(JBuffer buffer, int offset, int length);

	/**
	 * Crc32 ccitt continue.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @param crc
	 *          the crc
	 * @return the int
	 */
	public static int crc32CCITTContinue(JBuffer buffer,
			int offset,
			int length,
			int crc) {
		return crc32CCITTSeed(buffer, offset, length, ~crc);
	}

	/**
	 * Crc32 ccitt seed.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @param seed
	 *          the seed
	 * @return the int
	 */
	public static native int crc32CCITTSeed(JBuffer buffer,
			int offset,
			int length,
			int seed);

	/**
	 * Crc32 iee e802.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the long
	 */
	public static native long crc32IEEE802(JBuffer buffer, int offset, int length);

	/**
	 * Flip.
	 * 
	 * @param c
	 *          the c
	 * @return the long
	 */
	public static long flip(long c) {
		return ((c >> 0 & 0xFF) << 24) | ((c >> 8 & 0xFF) << 16)
				| ((c >> 16 & 0xFF) << 8) | ((c >> 24 & 0xFF) << 0);
	}

	/**
	 * Icmp.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param ipOffset
	 *          the ip offset
	 * @param icmpOffset
	 *          the icmp offset
	 * @return the int
	 */
	public static native int icmp(JBuffer buffer, int ipOffset, int icmpOffset);

	/**
	 * In checksum.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the int
	 */
	public static native int inChecksum(JBuffer buffer, int offset, int length);

	/**
	 * In checksum should be.
	 * 
	 * @param checksum
	 *          the checksum
	 * @param calculateChecksum
	 *          the calculate checksum
	 * @return the int
	 */
	public static native int inChecksumShouldBe(int checksum,
			int calculateChecksum);

	/**
	 * Pseudo tcp.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param ipOffset
	 *          the ip offset
	 * @param tcpOffset
	 *          the tcp offset
	 * @return the int
	 */
	public static native int pseudoTcp(JBuffer buffer, int ipOffset, int tcpOffset);

	/**
	 * Pseudo udp.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param ipOffset
	 *          the ip offset
	 * @param udpOffset
	 *          the udp offset
	 * @return the int
	 */
	public static native int pseudoUdp(JBuffer buffer, int ipOffset, int udpOffset);

}
