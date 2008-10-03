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
package org.jnetpcap;

/**
 * A peered number pointer class that stores and retrieves number values from
 * native/direct memory locations. This class facilitates exchange of number
 * values (from bytes to doubles) to various native functions. The key being
 * that these numbers at JNI level can be passed in as pointers and thus allows
 * natives methods to both send and receive values between native and java
 * space. The methods are named similarly like java.lang.Number class, with the
 * exception of setter methods.
 * <p>
 * Typical usage for JNumber is to use it wherever a system request a primitive
 * type pointer.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JNumber
    extends Peered {

	private static final int ALLOC_SIZE = 8; // 8 bytes

	/**
	 * @param size
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

}
