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
package org.jnetpcap.util;

import org.jnetpcap.nio.JBuffer;

/**
 * Various data manipulation utilities.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class DataUtils {
	
	/**
	 * Returns the difference between b1 and b2. b1 is subtracted from b2.
	 * 
	 * @param b1
	 * @param b2
	 * @return array containing the different between b1 and b2
	 */
	public static byte[] diff(final JBuffer b1, final JBuffer b2) {
		return diff(b1.getByteArray(0, b1.size()), b2.getByteArray(0, b2.size()));
	}

	
	/**
	 * Returns the difference between b1 and b2. b1 is subtracted from b2.
	 * 
	 * @param b1
	 * @param b2
	 * @return array containing the different between b1 and b2
	 */
	public static byte[] diff(final byte[] b1, final JBuffer b2) {
		return diff(b1, b2.getByteArray(0, b2.size()));
	}

	/**
	 * Returns the difference between b1 and b2. b1 is subtracted from b2.
	 * 
	 * @param b1
	 * @param b2
	 * @return array containing the different between b1 and b2
	 */
	public static byte[] diff(final byte[] b1, final byte[] b2) {

		final int max = (b1.length > b2.length) ? b1.length : b2.length;
		final byte[] b = new byte[max];

		for (int i = 0; i < max; i++) {

			final byte t1 = (i < b1.length) ? b1[i] : 0;
			final byte t2 = (i < b2.length) ? b2[i] : 0;

			b[i] = (byte) (t2 - t1);
		}
		
		return b;
	}
}
