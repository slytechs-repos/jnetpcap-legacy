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

import java.nio.ByteOrder;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JByteBuffer {
	public byte getByte(int index);

	public byte[] getByteArray(int index, byte[] array);

	public byte[] getByteArray(int index, int size);

	public double getDouble(int index);

	public float getFloat(int index);

	public int getInt(int index);

	public long getLong(int index);

	public short getShort(int index);

	public int getUByte(int index);

	public long getUInt(int index);

	public int getUShort(int index);

	public void setByte(int index, byte value);

	public void setByteArray(int index, byte[] array);

	public void setDouble(int index, double value);

	public void setFloat(int index, float value);

	public void setInt(int index, int value);

	public void setLong(int index, long value);

	public void setShort(int index, short value);

	public void setUByte(int index, int value);

	public void setUInt(int index, long value);

	public void setUShort(int index, int value);
	
	public int size();
	
	public ByteOrder order();
	
	public void order(ByteOrder order);

}
