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

import java.nio.ByteBuffer;

/**
 * A peered number pointer class that stores and retrieves number values from
 * native/direct memory locations. This class facilitates exchange of number
 * values (from bytes to doubles) to various native functions. The key being
 * that these numbers at JNI level can be passed in as pointers and thus allows
 * natives methods to both send and receive values between native and java
 * space. The methods are named similarly like java.lang.Number class, with the
 * exception of existance of setter methods.
 * <p>
 * Typical usage for JNumber is to use it wherever a function requests a
 * primitive type pointer.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class JNumber
    extends
    JMemory {

	/**
	 * Used to request a specific type of primitive that this number will be
	 * dealing with possibly allocating memory more efficiently to fit the
	 * primitive type.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Type {
		/**
		 * 8-bit integer
		 */
		BYTE,

		/**
		 * 16-bit UTF character
		 */
		CHAR,

		/**
		 * 32-bit integer
		 */
		INT,

		/**
		 * 16-bit integer
		 */
		SHORT,

		/**
		 * 64-bit integer
		 */
		LONG,

		/**
		 * A floating point value
		 */
		FLOAT,

		/**
		 * A long floating point value
		 */
		DOUBLE;

		/**
		 * Size in bytes for this native type on this machine
		 */
		public final int size;

		private static int biggestSize = 0;

		Type() {
			size = JNumber.sizeof(ordinal());
		}

		/**
		 * Returns the size of the biggets primitive
		 * 
		 * @return size in bytes of the biggest primitive on this platform
		 */
		public static int getBiggestSize() {
			if (biggestSize == 0) {
				for (Type t : values()) {
					if (t.size > biggestSize) {
						biggestSize = t.size;
					}
				}
			}

			return biggestSize;
		}
	}

	/*
	 * Although these are private they are still exported to a JNI header file
	 * where our private sizeof(int) function can use these constants to lookup
	 * the correct primitive size
	 */
	private final static int BYTE_ORDINAL = 0;

	private final static int CHAR_ORDINAL = 1;

	private final static int INT_ORDINAL = 2;

	private final static int SHORT_ORDINAL = 3;

	private final static int LONG_ORDINAL = 4;

	private final static int LONG_LONG_ORDINAL = 5;

	private final static int FLOAT_ORDINAL = 6;

	private final static int DOUBLE_ORDINAL = 7;

	private final static int MAX_SIZE_ORDINAL = 8;

	/**
	 * Allocates a JNumber object capable of storing the biggest primitive on this
	 * platform.
	 */
	public JNumber() {
		super(Type.getBiggestSize());
	}

	/**
	 * Allocates a number of the specified size and type.
	 * 
	 * @param type
	 *          primitive type for which to allocate memory
	 */
	public JNumber(Type type) {
		super(type.size);
	}

	/**
	 * Creates a number pointer, which does not allocate any memory on its own,
	 * but needs to be peered with primitive pointer.
	 * 
	 * @param type
	 *          memory model
	 */
	public JNumber(JMemory.Type type) {
		super(type);
	}

	private native static int sizeof(int oridnal);

	/**
	 * Returns the data from this JNUmber as a signed integer
	 * 
	 * @return java signed integer
	 */
	public native int intValue();

	/**
	 * Sets new value in native memory
	 * 
	 * @param value
	 *          new value
	 */
	public native void intValue(int value);

	/**
	 * Gets value from native memory
	 * 
	 * @return java signed byte
	 */
	public native byte byteValue();

	/**
	 * Sets new value in native memory
	 * 
	 * @param value
	 *          new value
	 */
	public native void byteValue(byte value);

	/**
	 * Gets value from native memory
	 * 
	 * @return java signed short
	 */
	public native short shortValue();

	/**
	 * Sets new value in native memory
	 * 
	 * @param value
	 *          new value
	 */
	public native void shortValue(short value);

	/**
	 * Gets value from native memory
	 * 
	 * @return java signed long
	 */
	public native long longValue();

	/**
	 * Sets new value in native memory
	 * 
	 * @param value
	 *          new value
	 */
	public native void longValue(long value);

	/**
	 * Gets value from native memory
	 * 
	 * @return java float
	 */
	public native float floatValue();

	/**
	 * Sets new value in native memory
	 * 
	 * @param value
	 *          new value
	 */
	public native void floatValue(float value);

	/**
	 * Gets value from native memory
	 * 
	 * @return java double float
	 */
	public native double doubleValue();

	/**
	 * Sets new value in native memory
	 * 
	 * @param value
	 *          new value
	 */
	public native void doubleValue(double value);

	/**
	 * Peers with supplied number object
	 * 
	 * @param number
	 *          number object to peer with
	 * @return number of bytes peered
	 */
	public int peer(JNumber number) {
		return super.peer(number);
	}

	/**
	 * Peers with supplied buffer object
	 * 
	 * @param buffer
	 *          buffer to peer with
	 * @return number of bytes peered
	 */
	public int peer(JBuffer buffer) {
		return super.peer(buffer, 0, size());
	}

	/**
	 * Peers with supplied buffer object
	 * 
	 * @param buffer
	 *          buffer to peer with
	 * @param offset
	 *          offset into supplied buffer
	 * @return number of bytes peered
	 */
	public int peer(JBuffer buffer, int offset) {
		return super.peer(buffer, offset, size());
	}

	/**
	 * Copies data out of the supplied buffer into this number object
	 * 
	 * @param buffer
	 *          buffer to copy data out of. Buffer's position and limit properties
	 *          set the bounds for the copy
	 * @return number of bytes copied
	 */
	@Override
  public int transferFrom(ByteBuffer buffer) {
		return super.transferFrom(buffer);
	}
}
