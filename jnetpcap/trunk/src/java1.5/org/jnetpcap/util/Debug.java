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

import org.jnetpcap.nio.JStruct;

/**
 * Specialized debug class that provides debugging and tracing services. There
 * is a low level native debug object compiled into jnetpcap library. The native
 * trace debugger works similar to the way that java logger's do with message
 * levels that can be set which will allow debug information to be printed out.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Debug
    extends
    JStruct {

	/**
	 * Size of native debug_t structure
	 * 
	 * @return size in bytes
	 */
	public native static int sizeof();

	/**
	 * @param structName
	 */
	public Debug() {
		super("class Debug", sizeof());
	}

	/**
	 * Provides access to raw level value
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public interface LevelId {

		/**
		 * Gets the numerical id for this priority level
		 * 
		 * @return numerical id
		 * @see org.jnetpcap.util.Debug.LevelId#intValue()
		 */
		public int intValue();
	}

	/**
	 * Defines various message severity levels
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Level implements LevelId {
		ERROR(4),
		WARN(6),
		INFO(8),
		TRACE(10);

		private final int level;

		private Level(int level) {
			this.level = level;
		}

		/**
		 * Gets the numerical id for this level constant
		 * 
		 * @return numerical id
		 * @see org.jnetpcap.util.Debug.LevelId#intValue()
		 */
		public int intValue() {
			return level;
		}

		public static Level valueOf(int level) {
			for (Level l : values()) {
				if (l.level == level) {
					return l;
				}
			}

			return null;
		}
	}

	public void setLevel(Debug.LevelId level) {
		setLevel(level.intValue());
	}

	public native void setLevel(int level);

	public native int getLevel();

	public Level getLevelEnum() {
		return Level.valueOf(getLevel());
	}
}
