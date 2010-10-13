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
 * TODO: remove
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("all")
public class JStructBuffer
    extends JObjectBuffer {

	protected interface JStructField extends Offset {
		
		/**
		 * Length of the field
		 * 
		 * @param offset 
		 * @return
		 */
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
	public JStructBuffer(JStructField[]... fields) {
		super(calcSize(fields));
	}

	protected static int calcSize(JStructField[]... fields) {
		int l = 0;

		for (JStructField[] fs : fields) {
			for (JStructField f: fs) {
				l += f.length(l);
			}
		}

		return l;
	}

}
