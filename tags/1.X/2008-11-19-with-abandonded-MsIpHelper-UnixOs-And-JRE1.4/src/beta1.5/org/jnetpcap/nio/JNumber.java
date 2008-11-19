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
public class JNumber
    extends JMemory {

	/**
	 * Number of bytes to allocate to hold our number. 16 bytes is a bit much,
	 * typically 8 would be sufficient to hold even a double, but on 64 bit
	 * machines and even newer ones that this may eventually run on, it is better
	 * to overallocate than run into a limit.
	 */
	private static final int ALLOC_SIZE = 16;

	/**
	 * Allocates a number of the specified size.
	 * 
	 * @param size
	 *          number of byte to allocate to hold a number
	 */
	public JNumber(int size) {
		super(size);
	}

	/**
	 * Allocates a number with default size. The size is large enough to hold the
	 * biggest number.
	 */
	public JNumber() {
		super(ALLOC_SIZE);
	}

	public native int intValue();

	public native void intValue(int value);

	public native byte byteValue();

	public native void byteValue(byte value);

	public native short shortValue();

	public native void shortValue(short value);

	public native long longValue();

	public native void longValue(long value);

	public native float floatValue();

	public native void floatValue(float value);

	public native double doubleValue();

	public native void doubleValue(double value);
	
	public int peer(ByteBuffer peer) {
		return super.peer(peer);
	}
	
	public int transferFrom(ByteBuffer peer) {
		return super.peer(peer);
	}

}
