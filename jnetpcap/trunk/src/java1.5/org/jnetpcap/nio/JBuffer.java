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

	/**
	 * Gets a signed 8-bit value.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value from the buffer
	 */
	public native byte getByte(int index);

	/**
	 * Gets byte data from buffer and stores it in supplied array buffer
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param array
	 *          byte array used to store the result where the length of the byte
	 *          array determines the number of bytes to be copied from the buffer
	 * @return same array object passed in
	 */
	public native byte[] getByteArray(int index, byte[] array);

	/**
	 * Gets the byte data from buffer and stores into newly allocated byte array
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param size
	 *          number of bytes to copy and the size of the newly allocated byte
	 *          array
	 * @return reference to new byte array containing the copied data
	 */
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
	public native byte[] getByteArray(
	    int index,
	    byte[] array,
	    int offset,
	    int length);

	/**
	 * Gets the java double value out of the buffer
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer
	 */
	public native double getDouble(int index);

	/**
	 * Gets the java float value out of the buffer
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer
	 */
	public native float getFloat(int index);

	/**
	 * Gets the java signed integer value from the buffer
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer
	 */
	public native int getInt(int index);

	/**
	 * Gets the java signed long value from the buffer
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer
	 */
	public native long getLong(int index);

	/**
	 * Gets the java signed short value from the buffer
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer
	 */
	public native short getShort(int index);

	/**
	 * Gets the java usigned byte value
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer as next bigger java primitive type so
	 *         that the sign of the value can be preserved since java does not
	 *         allow unsigned primitives
	 */
	public native int getUByte(int index);

	/**
	 * Gets the java usigned int value
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer as next bigger java primitive type so
	 *         that the sign of the value can be preserved since java does not
	 *         allow unsigned primitives
	 */
	public native long getUInt(int index);

	/**
	 * Gets the java usigned short value
	 * 
	 * @param index
	 *          offset into the buffer
	 * @return value read from the buffer as next bigger java primitive type so
	 *         that the sign of the value can be preserved since java does not
	 *         allow unsigned primitives
	 */
	public native int getUShort(int index);

	/**
	 * Find the delimiter array of chars within the buffer.
	 * 
	 * @param index
	 *          starting offset into the buffer
	 * @param delimeter
	 *          array of chars to search for
	 * @return number of delimeter chars matched
	 */
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

	/**
	 * Retrieves all the characters from the buffer upto the delimiter char
	 * sequence.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param buf
	 *          string buffer where to store the string retrieved from the buffer
	 * @param delimeter
	 *          array of chars which will mark the end of the string
	 * @return the string buffer containing the retrieved string
	 */
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
	 * Retrieves all the characters from the buffer upto the delimiter char
	 * sequence.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param delimeter
	 *          array of chars which will mark the end of the string
	 * @return the string retrieved from the buffer
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
	 * @param buf
	 *          string buffer where the retrieved string is stored
	 * @param length
	 *          number of bytes to convert
	 * @return buffer containing the retrieved string
	 */
	public StringBuilder getUTF8String(int index, StringBuilder buf, int length) {
		final int len = index + ((size() < length) ? size() : length);

		for (int i = index; i < len; i++) {
			char c = getUTF8Char(i);
			buf.append(c);
		}

		return buf;
	}

	/**
	 * Gets the specified number of characters as a string.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param length
	 *          number of UTF8 characters to retrieve
	 * @return retrived string
	 */
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

	/**
	 * Checks if this buffer is readonly. Read only buffers do not allow any
	 * mutable operations to be performed on the buffer.
	 * 
	 * @return true if this buffer is read-only, otherwise false
	 */
	public boolean isReadonly() {
		return readonly;
	}

	/**
	 * Gets the byte-order of this buffer. The buffer allows big and little endian
	 * byte ordering of the integer values accessed by this buffer.
	 * 
	 * @return byte order of this buffer
	 */
	public ByteOrder order() {
		return (order) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
	}

	/**
	 * Sets the byte ordering of integers for this buffer
	 * 
	 * @param order
	 *          the new byte order for this integer
	 */
	public void order(final ByteOrder order) {
		this.order = (order == ByteOrder.BIG_ENDIAN);
	}

	/**
	 * Peers this buffer with a new buffer. The peer buffer's properties position
	 * and limit are used as starting and ending offsets for the peer operation.
	 * 
	 * @param peer
	 *          the buffer to peer with
	 * @return number of byte peered
	 */
	@Override
	public int peer(final ByteBuffer peer) throws PeeringException {
		setReadonly(peer.isReadOnly());
		return super.peer(peer);
	}

	/**
	 * Peers this buffer with the new buffer. The entire range of the buffer are
	 * peered.
	 * 
	 * @param peer
	 *          the buffer to peer with
	 * @return number of bytes peered
	 */
	public int peer(final JBuffer peer) {
		setReadonly(peer.isReadonly());
		return super.peer(peer);
	}

	/**
	 * Peers this buffer with a new buffer.
	 * 
	 * @param peer
	 *          buffer to peer with
	 * @param offset
	 *          offset into the new peer buffer
	 * @param length
	 *          number of bytes to peer
	 * @return number of bytes peered
	 * @throws IndexOutOfBoundsException
	 *           if offset and/or length are out of bounds
	 */
	public int peer(final JBuffer peer, final int offset, final int length)
	    throws IndexOutOfBoundsException {
		setReadonly(peer.isReadonly());
		return super.peer(peer, offset, length);
	}

	/**
	 * Sets a value in the buffer
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new value to be stored in the buffer
	 */
	public native void setByte(int index, byte value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param array
	 *          Array containing data to be set within the buffer. The length of
	 *          the buffer determines the number of bytes to be copied into the
	 *          buffer.
	 */
	public native void setByteArray(int index, byte[] array);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new double value to be stored within the buffer
	 */
	public native void setDouble(int index, double value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new float value to be stored within the buffer
	 */
	public native void setFloat(int index, float value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new int value to be stored within the buffer
	 */
	public native void setInt(int index, int value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new long value to be stored within the buffer
	 */
	public native void setLong(int index, long value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new short value to be stored within the buffer
	 */
	public native void setShort(int index, short value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new usigned byte value to be stored within the buffer
	 */
	public native void setUByte(int index, int value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new usigned int value to be stored within the buffer
	 */
	public native void setUInt(int index, long value);

	/**
	 * Sets a value in the buffer.
	 * 
	 * @param index
	 *          offset into the buffer
	 * @param value
	 *          new unsigned short value to be stored within the buffer
	 */
	public native void setUShort(int index, int value);

	/**
	 * Copies contents of the supplied buffer into this buffer
	 * 
	 * @param buffer
	 *          Source buffer to copy from. The array length determines the number
	 *          of bytes to copy.
	 * @return number of bytes copied
	 */
	@Override
  public int transferFrom(byte[] buffer) {
		return super.transferFrom(buffer);
	}

	/**
	 * Copies contents of the supplied buffer into this buffer
	 * 
	 * @param src
	 *          Source buffer to copy from. The position and limit properties of
	 *          the buffer determine the bounds of the copy.
	 * @param dstOffset
	 *          offset into this buffer where to start the copy
	 * @return number of bytes copied
	 */
	@Override
	public int transferFrom(final ByteBuffer src, final int dstOffset) {
		return super.transferFrom(src, dstOffset);
	}

	/**
	 * Copies contents of the supplied buffer into this buffer
	 * 
	 * @param buffer
	 *          Source buffer. The length of the source buffer determines the
	 *          number of bytes to be copied.
	 * @return number of bytes copied
	 */
	public int transferFrom(JBuffer buffer) {
		return buffer.transferTo(this);
	}

	/**
	 * Copies contents of this buffer into supplied buffer.
	 * 
	 * @param dst
	 *          destination buffer where to copy data to
	 * @param srcOffset
	 *          offset into this buffer where to start the copy
	 * @param length
	 *          number of bytes to copy
	 * @return number of bytes copied
	 */
	@Override
	public int transferTo(
	    final ByteBuffer dst,
	    final int srcOffset,
	    final int length) {
		return super.transferTo(dst, srcOffset, length);
	}

	/**
	 * Copies the contents of this buffer into the supplied buffer
	 * 
	 * @param dst
	 *          Destination buffer where to copy to. The number of bytes copied is
	 *          determined by the size of source buffer.
	 * @return number of bytes copied
	 */
	public int transferTo(final JBuffer dst) {
		return super.transferTo(dst);
	}

	/**
	 * Copies the contents of thsi buffer into the supplied buffer
	 * 
	 * @param dst
	 *          destination buffer where to copy to
	 * @param srcOffset
	 *          offset into the source buffer where to start copy from
	 * @param length
	 *          number of bytes to copy
	 * @param dstOffset
	 *          offset into the destination buffer where to start copy to
	 * @return number of bytes copied
	 */
	@Override
	public int transferTo(
	    final JBuffer dst,
	    final int srcOffset,
	    final int length,
	    final int dstOffset) {
		return super.transferTo(dst, srcOffset, length, dstOffset);
	}

	/**
	 * Sets this buffer as either read-only or read-write. Read-only mode disables
	 * all mutable operations on this buffer.
	 * 
	 * @param readonly
	 *          buffer accessor mode
	 */
	private final void setReadonly(boolean readonly) {
		this.readonly = readonly;
	}

	/**
	 * Sets data within this buffer
	 * 
	 * @param index
	 *          offset into this buffer
	 * @param data
	 *          data to copy into this buffer. The position and limit of the data
	 *          buffer set the bounds of the copy
	 */
	public native void setByteBuffer(int index, ByteBuffer data);

	/**
	 * Peers this object with the supplied object. This object will be pointing at
	 * the same memory as the supplied object.
	 * 
	 * @param src
	 *          source object that holds the memory location and size this object
	 *          will point to
	 * @return size of the src and this object
	 */
	@Override
  public int peer(JMemory src) {
		return super.peer(src);
	}
}