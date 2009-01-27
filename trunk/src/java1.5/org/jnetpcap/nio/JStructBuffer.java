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
package org.jnetpcap.nio;

import org.jnetpcap.util.Offset;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JStructBuffer
    extends JObjectBuffer {

	protected interface JStructField extends Offset {
		public int length(int offset);

	}

	/**
	 * @param peer
	 */
	public JStructBuffer(JMemory peer) {
		super(peer);
	}

	/**
	 * @param type
	 */
	public JStructBuffer(org.jnetpcap.nio.JMemory.Type type) {
		super(type);
	}

	/**
	 * The enum field tables are queried for the size of the overall structure.
	 * The tables are layouted in memory one after the other in the order they are
	 * supplied to this constructor. Each structure field within each tables is
	 * also layed out according to its ordinal order.
	 * 
	 * @param fields
	 *          vararg list of field enum tables
	 */
	public <T extends Enum<T> & JStructField> JStructBuffer(Class<T>... fields) {
		super(calcSize(fields));
	}

	protected static <T extends Enum<T> & JStructField> int calcSize(
	    Class<T>... fields) {
		int l = 0;

		for (Class<T> c : fields) {
			for (JStructField f : c.getEnumConstants()) {
				l += f.length(l);
			}
		}

		return l;
	}

}
