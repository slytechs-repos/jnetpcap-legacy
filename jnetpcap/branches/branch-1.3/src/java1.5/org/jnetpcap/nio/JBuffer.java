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

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.packet.PeeringException;

// TODO: Auto-generated Javadoc
/**
 * The Class JBuffer.
 */
public class JBuffer extends JMemory {

	/**
	 * 
	 */
	static {
		initIds();
	}

	/**
	 * Inits the ids.
	 */
	private native static void initIds();

	/** The order. */
	private volatile boolean order =
			(ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN);

	/** The readonly. */
	private boolean readonly = false;

	/**
	 * Instantiates a new j buffer.
	 * 
	 * @param type
	 *          the type
	 */
	public JBuffer(Type type) {
		super(type);
	}

	/**
	 * Instantiates a new j buffer.
	 * 
	 * @param peer
	 *          the peer
	 */
	public JBuffer(final ByteBuffer peer) {
		super(peer);
	}

	/**
	 * Instantiates a new j buffer.
	 * 
	 * @param size
	 *          the size
	 */
	public JBuffer(final int size) {
		super(size);
	}

	/**
	 * Instantiates a new j buffer.
	 * 
	 * @param peer
	 *          the peer
	 */
	public JBuffer(final JMemory peer) {
		super(peer);
	}

	/**
	 * Check.
	 * 
	 * @param index
	 *          the index
	 * @param len
	 *          the len
	 * @param address
	 *          the address
	 * @return the int
	 */
	private final int check(int index, int len, long address) {
		if (address == 0L) {
			throw new NullPointerException();
		}

		if (index < 0 || index + len > size) {
			throw new BufferUnderflowException();
		}

		return index;
	}

	/**
	 * Instantiates a new j buffer.
	 * 
	 * @param data
	 *          the data
	 */
	public JBuffer(byte[] data) {
		super(data.length);
		setByteArray(0, data);
	}

	/**
	 * Gets the byte.
	 * 
	 * @param index
	 *          the index
	 * @return the byte
	 */
	public byte getByte(int index) {
		return getByte0(physical, check(index, 1, physical));
	}

	/**
	 * Gets the byte0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @return the byte0
	 */
	private native static byte getByte0(long address, int index);

	/**
	 * Gets the byte array.
	 * 
	 * @param index
	 *          the index
	 * @param array
	 *          the array
	 * @return the byte array
	 */
	public byte[] getByteArray(int index, byte[] array) {
		return getByteArray(index, array, 0, array.length);
	}

	/**
	 * Gets the byte array.
	 * 
	 * @param index
	 *          the index
	 * @param size
	 *          the size
	 * @return the byte array
	 */
	public byte[] getByteArray(int index, int size) {
		return getByteArray(index, new byte[size], 0, size);
	}

	/**
	 * Gets the byte array.
	 * 
	 * @param index
	 *          the index
	 * @param array
	 *          the array
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the byte array
	 */
	public byte[] getByteArray(int index, byte[] array, int offset, int length) {

		if (array == null) {
			throw new NullPointerException();
		}

		if (offset < 0 || offset + length > array.length) {
			throw new ArrayIndexOutOfBoundsException();
		}

		return getByteArray0(physical,
				check(index, length, physical),
				array,
				array.length,
				offset,
				length);
	}

	/**
	 * Gets the byte array0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @param array
	 *          the array
	 * @param arrayLength
	 *          the array length
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the byte array0
	 */
	private static native byte[] getByteArray0(long address,
			int index,
			byte[] array,
			int arrayLength,
			int offset,
			int length);

	/**
	 * Gets the double.
	 * 
	 * @param index
	 *          the index
	 * @return the double
	 */
	public double getDouble(int index) {
		return getDouble0(physical, order, check(index, 8, physical));
	}

	/**
	 * Gets the double0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the double0
	 */
	private static native double getDouble0(long address, boolean order, int index);

	/**
	 * Gets the float.
	 * 
	 * @param index
	 *          the index
	 * @return the float
	 */
	public float getFloat(int index) {
		return getFloat0(physical, order, check(index, 4, physical));
	}

	/**
	 * Gets the float0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the float0
	 */
	private static native float getFloat0(long address, boolean order, int index);

	/**
	 * Gets the int.
	 * 
	 * @param index
	 *          the index
	 * @return the int
	 */
	public int getInt(int index) {
		return getInt0(physical, order, check(index, 4, physical));
	}

	/**
	 * Gets the int0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the int0
	 */
	private static native int getInt0(long address, boolean order, int index);

	/**
	 * Gets the long.
	 * 
	 * @param index
	 *          the index
	 * @return the long
	 */
	public long getLong(int index) {
		return getLong0(physical, order, check(index, 8, physical));
	}

	/**
	 * Gets the long0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the long0
	 */
	private static native long getLong0(long address, boolean order, int index);

	/**
	 * Gets the short.
	 * 
	 * @param index
	 *          the index
	 * @return the short
	 */
	public short getShort(int index) {
		return getShort0(physical, order, check(index, 2, physical));
	}

	/**
	 * Gets the short0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the short0
	 */
	private static native short getShort0(long address, boolean order, int index);

	/**
	 * Gets the u byte.
	 * 
	 * @param index
	 *          the index
	 * @return the u byte
	 */
	public int getUByte(int index) {
		return getUByte0(physical, check(index, 1, physical));
	}

	/**
	 * Gets the u byte0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @return the u byte0
	 */
	private static native int getUByte0(long address, int index);

	/**
	 * Gets the u int.
	 * 
	 * @param index
	 *          the index
	 * @return the u int
	 */
	public long getUInt(int index) {
		return getUInt0(physical, order, check(index, 4, physical));
	}

	/**
	 * Gets the u int0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the u int0
	 */
	private static native long getUInt0(long address, boolean order, int index);

	/**
	 * Gets the u short.
	 * 
	 * @param index
	 *          the index
	 * @return the u short
	 */
	public int getUShort(int index) {
		return getUShort0(physical, order, check(index, 2, physical));
	}

	/**
	 * Gets the u short0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @return the u short0
	 */
	private static native int getUShort0(long address, boolean order, int index);

	/**
	 * Find ut f8 string.
	 * 
	 * @param index
	 *          the index
	 * @param delimeter
	 *          the delimeter
	 * @return the int
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
	 * Gets the uT f8 string.
	 * 
	 * @param index
	 *          the index
	 * @param buf
	 *          the buf
	 * @param delimeter
	 *          the delimeter
	 * @return the uT f8 string
	 */
	public StringBuilder getUTF8String(int index,
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
	 * Gets the uT f8 string.
	 * 
	 * @param index
	 *          the index
	 * @param delimeter
	 *          the delimeter
	 * @return the uT f8 string
	 */
	public String getUTF8String(int index, char... delimeter) {
		final StringBuilder buf =
				getUTF8String(index, new StringBuilder(), delimeter);

		return buf.toString();
	}

	/**
	 * Gets the uT f8 string.
	 * 
	 * @param index
	 *          the index
	 * @param buf
	 *          the buf
	 * @param length
	 *          the length
	 * @return the uT f8 string
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
	 * Gets the uT f8 string.
	 * 
	 * @param index
	 *          the index
	 * @param length
	 *          the length
	 * @return the uT f8 string
	 */
	public String getUTF8String(int index, int length) {
		return getUTF8String(index, new StringBuilder(), length).toString();
	}

	/**
	 * Gets the uT f8 char.
	 * 
	 * @param index
	 *          the index
	 * @return the uT f8 char
	 */
	public char getUTF8Char(int index) {
		return (char) getUByte(index);
	}

	/**
	 * Checks if is the readonly.
	 * 
	 * @return the readonly
	 */
	public boolean isReadonly() {
		return readonly;
	}

	/**
	 * Order.
	 * 
	 * @return the byte order
	 */
	public ByteOrder order() {
		return (order) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
	}

	/**
	 * Order.
	 * 
	 * @param order
	 *          the order
	 */
	public void order(final ByteOrder order) {
		this.order = (order == ByteOrder.BIG_ENDIAN);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.nio.JMemory#peer(java.nio.ByteBuffer)
	 */
	@Override
	public int peer(final ByteBuffer peer) throws PeeringException {
		setReadonly(peer.isReadOnly());
		return super.peer(peer);
	}

	/**
	 * Peer.
	 * 
	 * @param peer
	 *          the peer
	 * @return the int
	 */
	public int peer(final JBuffer peer) {
		setReadonly(peer.isReadonly());
		return super.peer(peer);
	}

	/**
	 * Peer.
	 * 
	 * @param peer
	 *          the peer
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the int
	 * @throws IndexOutOfBoundsException
	 *           the index out of bounds exception
	 */
	public int peer(final JBuffer peer, final int offset, final int length)
			throws IndexOutOfBoundsException {
		setReadonly(peer.isReadonly());
		return super.peer(peer, offset, length);
	}

	/**
	 * Sets the byte.
	 * 
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public void setByte(int index, byte value) {
		setByte0(physical, check(index, 1, physical), value);
	}

	/**
	 * Sets the byte0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setByte0(long address, int index, byte value);

	/**
	 * Sets the byte array.
	 * 
	 * @param index
	 *          the index
	 * @param array
	 *          the array
	 */
	public void setByteArray(int index, byte[] array) {
		setByteArray0(physical,
				check(index, array.length, physical),
				array,
				array.length);
	}

	/**
	 * Sets the byte array0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @param array
	 *          the array
	 * @param arrayLength
	 *          the array length
	 */
	private static native void setByteArray0(long address,
			int index,
			byte[] array,
			int arrayLength);

	/**
	 * Sets the double.
	 * 
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public void setDouble(int index, double value) {
		setDouble0(physical, order, check(index, 8, physical), value);
	}

	/**
	 * Sets the double0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setDouble0(long address,
			boolean order,
			int index,
			double value);

	/**
	 * Sets the float.
	 * 
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public void setFloat(int index, float value) {
		setFloat0(physical, order, check(index, 4, physical), value);
	}

	/**
	 * Sets the float0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setFloat0(long address,
			boolean order,
			int index,
			float value);

	/**
	 * Sets the int.
	 * 
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public void setInt(int index, int value) {
		setInt0(physical, order, check(index, 4, physical), value);
	}

	/**
	 * Sets the int0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setInt0(long address,
			boolean order,
			int index,
			int value);

	/**
	 * Sets the long.
	 * 
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public void setLong(int index, long value) {
		setLong0(physical, order, check(index, 8, physical), value);
	}

	/**
	 * Sets the long0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setLong0(long address,
			boolean order,
			int index,
			long value);

	/**
	 * Sets the short.
	 * 
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public void setShort(int index, short value) {
		setShort0(physical, order, check(index, 2, physical), value);
	}

	/**
	 * Sets the short0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public static native void setShort0(long address,
			boolean order,
			int index,
			short value);

	/**
	 * Sets the u byte.
	 * 
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public void setUByte(int index, int value) {
		setUByte0(physical, check(index, 1, physical), value);
	}

	/**
	 * Sets the u byte0.
	 * 
	 * @param address
	 *          the address
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setUByte0(long address, int index, int value);

	/**
	 * Sets the u int.
	 * 
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public void setUInt(int index, long value) {
		setUInt0(physical, order, check(index, 4, physical), value);
	}

	/**
	 * Sets the u int0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setUInt0(long address,
			boolean order,
			int index,
			long value);

	/**
	 * Sets the u short.
	 * 
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	public void setUShort(int index, int value) {
		setUShort0(physical, order, check(index, 2, physical), value);
	}

	/**
	 * Sets the u short0.
	 * 
	 * @param address
	 *          the address
	 * @param order
	 *          the order
	 * @param index
	 *          the index
	 * @param value
	 *          the value
	 */
	private static native void setUShort0(long address,
			boolean order,
			int index,
			int value);

	/* (non-Javadoc)
	 * @see org.jnetpcap.nio.JMemory#transferFrom(byte[])
	 */
	@Override
	public int transferFrom(byte[] buffer) {
		return super.transferFrom(buffer);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.nio.JMemory#transferFrom(java.nio.ByteBuffer, int)
	 */
	@Override
	public int transferFrom(final ByteBuffer src, final int dstOffset) {
		return super.transferFrom(src, dstOffset);
	}

	/**
	 * Transfer from.
	 * 
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public int transferFrom(JBuffer buffer) {
		return buffer.transferTo(this);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.nio.JMemory#transferTo(java.nio.ByteBuffer, int, int)
	 */
	@Override
	public int transferTo(final ByteBuffer dst,
			final int srcOffset,
			final int length) {
		return super.transferTo(dst, srcOffset, length);
	}

	/**
	 * Transfer to.
	 * 
	 * @param dst
	 *          the dst
	 * @return the int
	 */
	public int transferTo(final JBuffer dst) {
		return super.transferTo(dst);
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.nio.JMemory#transferTo(org.jnetpcap.nio.JBuffer, int, int, int)
	 */
	@Override
	public int transferTo(final JBuffer dst,
			final int srcOffset,
			final int length,
			final int dstOffset) {
		return super.transferTo(dst, srcOffset, length, dstOffset);
	}

	/**
	 * Sets the readonly.
	 * 
	 * @param readonly
	 *          the new readonly
	 */
	private final void setReadonly(boolean readonly) {
		this.readonly = readonly;
	}

	/**
	 * Sets the byte buffer.
	 * 
	 * @param index
	 *          the index
	 * @param data
	 *          the data
	 */
	public native void setByteBuffer(int index, ByteBuffer data);

	/* (non-Javadoc)
	 * @see org.jnetpcap.nio.JMemory#peer(org.jnetpcap.nio.JMemory)
	 */
	@Override
	public int peer(JMemory src) {
		return super.peer(src);
	}
}
