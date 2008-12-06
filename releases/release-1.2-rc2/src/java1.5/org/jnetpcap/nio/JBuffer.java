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
 * A direct ByteBuffer stored in native memory
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JBuffer
    extends JMemory {

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
	 * @param type
	 *          TODO
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

	public native double getDouble(int index);

	public native float getFloat(int index);

	public native int getInt(int index);

	public native long getLong(int index);

	public native short getShort(int index);

	public native int getUByte(int index);

	public native long getUInt(int index);

	public native int getUShort(int index);

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

	@Override
	public int transferFrom(final ByteBuffer src, final int dstOffset) {
		return super.transferFrom(src, dstOffset);
	}

	@Override
	public int transferTo(final ByteBuffer dst, final int srcOffset,
	    final int length) {
		return super.transferTo(dst, srcOffset, length);
	}

	public int transferTo(final JBuffer dst) {
		return super.transferTo(dst);
	}

	public int transferTo(final JBuffer dst, final int srcOffset,
	    final int length, final int dstOffset) {
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