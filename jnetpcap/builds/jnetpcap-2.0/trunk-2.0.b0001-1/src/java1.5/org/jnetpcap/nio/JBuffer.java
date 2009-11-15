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
import java.nio.ByteOrder;

import org.jnetpcap.packet.PeeringException;

/**
 * A direct buffer stored in native memory
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JBuffer
    extends
    JMemory {

	/**
	 * 
	 */
	static {
		initIds();
	}

	/**
	 * JNI Ids
	 */
	private native static void initIds();

	/**
	 * True means BIG endian, false means LITTLE endian byte order
	 */
	private volatile boolean order =
	    (ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN);

	/**
	 * True means buffer is readonly, false means read/write buffer type
	 */
	private boolean readonly = false;

	/**
	 * Creates a 
	 * @param type
	 *          memory model
	 */
	public JBuffer(Type type) {
		super(type);
	}

	/**
	 * @param peer
	 */
	public JBuffer(final ByteBuffer peer) {
		super(peer);
	}

	/**
	 * @param size
	 */
	public JBuffer(final int size) {
		super(size);
	}

	/**
	 * @param peer
	 */
	public JBuffer(final JMemory peer) {
		super(peer);
	}

	/**
	 * @param data
	 */
	public JBuffer(byte[] data) {
		super(data.length);
		setByteArray(0, data);
	}

	public native byte getByte(int index);

	public native byte[] getByteArray(int index, byte[] array);

	public native byte[] getByteArray(int index, int size);

	/**
	 * Reads data from JBuffer into user supplied array.
	 * 
	 * @param index
	 *          starting position in the JBuffer
	 * @param array
	 *          destination array
	 * @param offset
	 *          starting position in the destination array
	 * @param length
	 *          maximum number of bytes to copy
	 * @return the actual number of bytes copied which could be less then
	 *         requested due to size of the JBuffer
	 */
	public native byte[] getByteArray(int index, byte[] array, int offset, int length);

	public native double getDouble(int index);

	public native float getFloat(int index);

	public native int getInt(int index);

	public native long getLong(int index);

	public native short getShort(int index);

	public native int getUByte(int index);

	public native long getUInt(int index);

	public native int getUShort(int index);

	public int findUTF8String(int index, char... delimeter) {

		final int size = size();

		int searchedLength = 0;
		int match = 0;
		for (int i = index; i < size; i++) {

			char c = getUTF8Char(i);
			char d = delimeter[match];

			if (Character.isDefined(c) == false) {
				break;
			}

			if (d == c) {
				match++;

				if (match == delimeter.length) {
					searchedLength = i - index + 1;
					break;
				}
			} else {
				match = 0;
			}
		}

		return searchedLength;
	}

	public StringBuilder getUTF8String(
	    int index,
	    StringBuilder buf,
	    char... delimeter) {

		final int size = size();
		final int len = index + size;

		int match = 0;
		for (int i = index; i < len; i++) {
			if (i >= size) {
				return buf;
			}

			if (match == delimeter.length) {
				break;
			}

			char c = getUTF8Char(i);
			buf.append(c);

			if (delimeter[match] == c) {
				match++;
			} else {
				match = 0;
			}
		}

		return buf;
	}

	/**
	 * Converts raw bytes to a java string. The delimeter is used to end the
	 * string or the end of the buffer is used. The delimiter is included in the
	 * returned string.
	 * 
	 * @param index
	 *          byte index into the buffer to start
	 * @param delimiter
	 *          delimiter series of chars to search for
	 * @return string which includes the delimiter
	 */
	public String getUTF8String(int index, char... delimeter) {
		final StringBuilder buf =
		    getUTF8String(index, new StringBuilder(), delimeter);

		return buf.toString();
	}

	/**
	 * Converts raw bytes to a java string. The length is the maximum length of
	 * the string to return.
	 * 
	 * @param index
	 *          byte index into the buffer to start
	 * @param length
	 *          number of bytes to convert
	 * @return string of at most length bytes
	 */
	public StringBuilder getUTF8String(int index, StringBuilder buf, int length) {
		final int len = index + ((size() < length) ? size() : length);

		for (int i = index; i < len; i++) {
			char c = getUTF8Char(i);
			buf.append(c);
		}

		return buf;
	}

	public String getUTF8String(int index, int length) {
		return getUTF8String(index, new StringBuilder(), length).toString();
	}

	/**
	 * Converts a single byte to a java char.
	 * 
	 * @param index
	 *          index into the buffer
	 * @return converted UTF8 char
	 */
	public char getUTF8Char(int index) {
		return (char) getUByte(index);
	}

	public boolean isReadonly() {
		return readonly;
	}

	public ByteOrder order() {
		return (order) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
	}

	public void order(final ByteOrder order) {
		this.order = (order == ByteOrder.BIG_ENDIAN);
	}

	@Override
	public int peer(final ByteBuffer peer) throws PeeringException {
		setReadonly(peer.isReadOnly());
		return super.peer(peer);
	}

	public int peer(final JBuffer peer) {
		setReadonly(peer.isReadonly());
		return super.peer(peer);
	}

	public int peer(final JBuffer peer, final int offset, final int length)
	    throws IndexOutOfBoundsException {
		setReadonly(peer.isReadonly());
		return super.peer(peer, offset, length);
	}

	public native void setByte(int index, byte value);

	public native void setByteArray(int index, byte[] array);

	public native void setDouble(int index, double value);

	public native void setFloat(int index, float value);

	public native void setInt(int index, int value);

	public native void setLong(int index, long value);

	public native void setShort(int index, short value);

	public native void setUByte(int index, int value);

	public native void setUInt(int index, long value);

	public native void setUShort(int index, int value);

	public int transferFrom(byte[] buffer) {
		return super.transferFrom(buffer);
	}

	@Override
	public int transferFrom(final ByteBuffer src, final int dstOffset) {
		return super.transferFrom(src, dstOffset);
	}

	public int transferFrom(JBuffer buffer) {
		return buffer.transferTo(this);
	}

	@Override
	public int transferTo(
	    final ByteBuffer dst,
	    final int srcOffset,
	    final int length) {
		return super.transferTo(dst, srcOffset, length);
	}

	public int transferTo(final JBuffer dst) {
		return super.transferTo(dst);
	}

	public int transferTo(
	    final JBuffer dst,
	    final int srcOffset,
	    final int length,
	    final int dstOffset) {
		return super.transferTo(dst, srcOffset, length, dstOffset);
	}

	private final void setReadonly(boolean readonly) {
		this.readonly = readonly;
	}

	/**
	 * @param i
	 * @param data
	 */
	public native void setByteBuffer(int i, ByteBuffer data);

	/**
	 * Peers this object with the supplied object. This object will be pointing at
	 * the same memory as the supplied object.
	 * 
	 * @param src
	 *          source object that holds the memory location and size this object
	 *          will point to
	 * @return size of the src and this object
	 */
	public int peer(JMemory src) {
		return super.peer(src);
	}
}