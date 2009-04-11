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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JMemoryPool;
import org.jnetpcap.nio.JNumber;
import org.jnetpcap.packet.PeeringException;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class SlidingBuffer {

	private long leftSequence = 0L;

	private long rightSequence = 0L;

	private final JBuffer storage;

	private final int size;

	public SlidingBuffer(int size) {
		this.size = size;

		/*
		 * Allocate round robin buffer with padding so that we can duplicate a few
		 * bytes at the right edge of the real offset. This way if we're asked to
		 * read a value that is wrapped around mid way at the end of the buffer, we
		 * can just safely read it since those bytes have been duplicated.
		 */
		this.storage = JMemoryPool.buffer(size + JNumber.Type.getBiggestSize());
	}

	public int findUTF8String(long sequence, char... delimeter) {
		return this.storage.findUTF8String(map(sequence), delimeter);
	}

	public byte getByte(long sequence) {
		return this.storage.getByte(map(sequence));
	}

	public byte[] getByteArray(long sequence, byte[] array) {
		return this.storage.getByteArray(map(sequence), array);
	}

	public byte[] getByteArray(long sequence, int size) {
		return this.storage.getByteArray(map(sequence), size);
	}

	public double getDouble(long sequence) {
		return this.storage.getDouble(map(sequence));
	}

	public float getFloat(long sequence) {
		return this.storage.getFloat(map(sequence));
	}

	public int getInt(long sequence) {
		return this.storage.getInt(map(sequence));
	}

	public long getLong(long sequence) {
		return this.storage.getLong(map(sequence));
	}

	public short getShort(long sequence) {
		return this.storage.getShort(map(sequence));
	}

	public int getUByte(long sequence) {
		return this.storage.getUByte(map(sequence));
	}

	public long getUInt(long sequence) {
		return this.storage.getUInt(map(sequence));
	}

	public int getUShort(long sequence) {
		return this.storage.getUShort(map(sequence));
	}

	public char getUTF8Char(long sequence) {
		return this.storage.getUTF8Char(map(sequence));
	}

	public String getUTF8String(long sequence, char... delimeter) {
		return this.storage.getUTF8String(map(sequence), delimeter);
	}

	public String getUTF8String(long sequence, int length) {
		return this.storage.getUTF8String(map(sequence), length);
	}

	public StringBuilder getUTF8String(
	    int sequence,
	    StringBuilder buf,
	    char... delimeter) {
		return this.storage.getUTF8String(map(sequence), buf, delimeter);
	}

	public StringBuilder getUTF8String(
	    long sequence,
	    StringBuilder buf,
	    int length) {
		return this.storage.getUTF8String(map(sequence), buf, length);
	}

	public int hashCode() {
		return this.storage.hashCode();
	}

	public boolean isInitialized() {
		return this.storage.isInitialized();
	}

	public boolean isJMemoryBasedOwner() {
		return this.storage.isJMemoryBasedOwner();
	}

	public final boolean isOwner() {
		return this.storage.isOwner();
	}

	public boolean isReadonly() {
		return this.storage.isReadonly();
	}

	public ByteOrder order() {
		return this.storage.order();
	}

	public void order(ByteOrder order) {
		this.storage.order(order);
	}

	public int peer(ByteBuffer peer) throws PeeringException {
		return this.storage.peer(peer);
	}

	public int peer(JBuffer peer, int offset, int length)
	    throws IndexOutOfBoundsException {
		return this.storage.peer(peer, offset, length);
	}

	public int peer(JBuffer peer) {
		return this.storage.peer(peer);
	}

	public int peer(JMemory src) {
		return this.storage.peer(src);
	}

	public void setByte(long sequence, byte value) {
		this.storage.setByte(map(sequence), value);
	}

	public void setByteArray(long sequence, byte[] array) {
		this.storage.setByteArray(map(sequence), array);
	}

	public void setByteBuffer(int i, ByteBuffer data) {
		this.storage.setByteBuffer(i, data);
	}

	public void setDouble(long sequence, double value) {
		this.storage.setDouble(map(sequence), value);
	}

	public void setFloat(long sequence, float value) {
		this.storage.setFloat(map(sequence), value);
	}

	public void setInt(long sequence, int value) {
		this.storage.setInt(map(sequence), value);
	}

	public void setLong(long sequence, long value) {
		this.storage.setLong(map(sequence), value);
	}

	public void setShort(long sequence, short value) {
		this.storage.setShort(map(sequence), value);
	}

	public void setUByte(long sequence, int value) {
		this.storage.setUByte(map(sequence), value);
	}

	public void setUInt(long sequence, long value) {
		this.storage.setUInt(map(sequence), value);
	}

	private int map(long sequence) {

		return (int) (sequence - leftSequence);
	}

	public void setUShort(long sequence, int value) {
		this.storage.setUShort(map(sequence), value);
	}

	public int length() {
		return (int) (rightSequence - leftSequence);
	}

	public String toDebugString() {
		return this.storage.toDebugString();
	}

	public String toHexdump() {
		return this.storage.toHexdump();
	}

	public String toHexdump(
	    int length,
	    boolean address,
	    boolean text,
	    boolean data) {
		return this.storage.toHexdump(length, address, text, data);
	}

	public String toString() {
		return this.storage.toString();
	}

	public int transferFrom(byte[] buffer) {
		return this.storage.transferFrom(buffer);
	}

	public int transferFrom(ByteBuffer src, int dstOffset) {
		return this.storage.transferFrom(src, (int) (dstOffset - leftSequence));
	}

	public int transferFrom(JBuffer buffer) {
		advance(buffer.size());
		return this.storage.transferFrom(buffer);
	}

	/**
	 * @param size
	 */
	private void advance(int size) {
		if (rightSequence + size > this.size) {
		}
	}

	public int transferTo(ByteBuffer dst, int srcOffset, int length) {
		return this.storage.transferTo(dst, (int) (srcOffset - leftSequence),
		    length);
	}

	public int transferTo(ByteBuffer dst) {
		return this.storage.transferTo(dst);
	}

	public int transferTo(JBuffer dst, int srcOffset, int length, int dstOffset) {
		return this.storage.transferTo(dst, (int) (srcOffset - leftSequence),
		    length, dstOffset);
	}

	public int transferTo(JBuffer dst) {
		return this.storage.transferTo(dst);
	}

}
