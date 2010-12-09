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
package org.jnetpcap.nio;

import java.nio.ByteBuffer;

// TODO: Auto-generated Javadoc
/**
 * The Class JNumber.
 */
public class JNumber
    extends
    JMemory {

	/**
	 * The Enum Type.
	 */
	public enum Type {
		
		/** The BYTE. */
		BYTE,

		/** The CHAR. */
		CHAR,

		/** The INT. */
		INT,

		/** The SHORT. */
		SHORT,

		/** The LONG. */
		LONG,

		/** The FLOAT. */
		FLOAT,

		/** The DOUBLE. */
		DOUBLE;

		/** The size. */
		public final int size;

		/** The biggest size. */
		private static int biggestSize = 0;

		/**
		 * Instantiates a new type.
		 */
		Type() {
			size = JNumber.sizeof(ordinal());
		}

		/**
		 * Gets the biggest size.
		 * 
		 * @return the biggest size
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
	/** The Constant BYTE_ORDINAL. */
	private final static int BYTE_ORDINAL = 0;

	/** The Constant CHAR_ORDINAL. */
	private final static int CHAR_ORDINAL = 1;

	/** The Constant INT_ORDINAL. */
	private final static int INT_ORDINAL = 2;

	/** The Constant SHORT_ORDINAL. */
	private final static int SHORT_ORDINAL = 3;

	/** The Constant LONG_ORDINAL. */
	private final static int LONG_ORDINAL = 4;

	/** The Constant LONG_LONG_ORDINAL. */
	private final static int LONG_LONG_ORDINAL = 5;

	/** The Constant FLOAT_ORDINAL. */
	private final static int FLOAT_ORDINAL = 6;

	/** The Constant DOUBLE_ORDINAL. */
	private final static int DOUBLE_ORDINAL = 7;

	/** The Constant MAX_SIZE_ORDINAL. */
	private final static int MAX_SIZE_ORDINAL = 8;

	/**
	 * Instantiates a new j number.
	 */
	public JNumber() {
		super(Type.getBiggestSize());
	}

	/**
	 * Instantiates a new j number.
	 * 
	 * @param type
	 *          the type
	 */
	public JNumber(Type type) {
		super(type.size);
	}

	/**
	 * Instantiates a new j number.
	 * 
	 * @param type
	 *          the type
	 */
	public JNumber(JMemory.Type type) {
		super(type);
	}

	/**
	 * Sizeof.
	 * 
	 * @param oridnal
	 *          the oridnal
	 * @return the int
	 */
	private native static int sizeof(int oridnal);

	/**
	 * Int value.
	 * 
	 * @return the int
	 */
	public native int intValue();

	/**
	 * Int value.
	 * 
	 * @param value
	 *          the value
	 */
	public native void intValue(int value);

	/**
	 * Byte value.
	 * 
	 * @return the byte
	 */
	public native byte byteValue();

	/**
	 * Byte value.
	 * 
	 * @param value
	 *          the value
	 */
	public native void byteValue(byte value);

	/**
	 * Short value.
	 * 
	 * @return the short
	 */
	public native short shortValue();

	/**
	 * Short value.
	 * 
	 * @param value
	 *          the value
	 */
	public native void shortValue(short value);

	/**
	 * Long value.
	 * 
	 * @return the long
	 */
	public native long longValue();

	/**
	 * Long value.
	 * 
	 * @param value
	 *          the value
	 */
	public native void longValue(long value);

	/**
	 * Float value.
	 * 
	 * @return the float
	 */
	public native float floatValue();

	/**
	 * Float value.
	 * 
	 * @param value
	 *          the value
	 */
	public native void floatValue(float value);

	/**
	 * Double value.
	 * 
	 * @return the double
	 */
	public native double doubleValue();

	/**
	 * Double value.
	 * 
	 * @param value
	 *          the value
	 */
	public native void doubleValue(double value);

	/**
	 * Peer.
	 * 
	 * @param number
	 *          the number
	 * @return the int
	 */
	public int peer(JNumber number) {
		return super.peer(number);
	}

	/**
	 * Peer.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int peer(JBuffer buffer) {
		return super.peer(buffer, 0, size());
	}

	/**
	 * Peer.
	 * 
	 * @param buffer
	 *          the buffer
	 * @param offset
	 *          the offset
	 * @return the int
	 */
	public int peer(JBuffer buffer, int offset) {
		return super.peer(buffer, offset, size());
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.nio.JMemory#transferFrom(java.nio.ByteBuffer)
	 */
	@Override
  public int transferFrom(ByteBuffer buffer) {
		return super.transferFrom(buffer);
	}
}
