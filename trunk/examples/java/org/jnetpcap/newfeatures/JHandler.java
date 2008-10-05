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
package org.jnetpcap.newfeatures;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.Peered;

/**
 * This is a test interface with classes imbeded for a possible replacement to
 * loop and dispatch handers. These replacements are based on the Peered class
 * and allow reuse of the allocated object to point pcap returned buffers in
 * memory. There are no plans to currently implement these, and they are checked
 * in simply as a way to allow a discussion and revision keeping on the entire
 * idea.
 * 
 * JHandler is the interface that dispatcher and loop would dispatch to. 
 * 
 * JBuffer is a new type of buffer that can be reused on every packet instead
 * of ByteBuffer which must be allocated every time. Further more PcapHeader
 * is simply an extension to JBuffer which hard codes the structure of the
 * pcap_pkthdr structure into Java.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JHandler<T> {

	public void nextPacket(PcapHeader header, JBuffer buffer, T user);

	public static class JBuffer
	    extends Peered {

		private boolean bigEndian = true;

		private boolean readonly = false;

		public boolean isReadonly() {
			return readonly;
		}

		public ByteOrder order() {
			return (bigEndian) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
		}

		public void order(ByteOrder order) {
			bigEndian = (order == ByteOrder.BIG_ENDIAN);
		}

		public native byte getByte(int index);

		public native short getShort(int index);

		public native int getInt(int index);

		public native long getLong(int index);

		public native float getFloat(int index);

		public native double getDouble(int index);

		public native int getUByte(int index);

		public native int getUShort(int index);

		public native long getUInt(int index);

		public native void setByte(int index, byte value);

		public native void setShort(int index, short value);

		public native void setInt(int index, int value);

		public native void setLong(int index, long value);

		public native void setFloat(int index, float value);

		public native void setDouble(int index, double value);

		public native void setUByte(int index, int value);

		public native void setUShort(int index, int value);

		public native void setUInt(int index, long value);

		public native int transferTo(ByteBuffer buffer);

		public native int transferFrom(ByteBuffer buffer);

		public native int transferTo(byte[] buffer);

		public native int transferFrom(byte[] buffer);

		public native ByteBuffer toByteBuffer();
	}

	public static class PcapHeader
	    extends JBuffer {

		public final static int FIELD_SECONDS = 0;

		public final static int FIELD_USECONDS = 8;

		public final static int FIELD_CAPLEN = 12;

		public final static int FIELD_WIRELEN = 16;

		public long seconds() {
			return getLong(FIELD_SECONDS);
		}

		public int useconds() {
			return getInt(FIELD_USECONDS);
		}

		public int caplen() {
			return getInt(FIELD_CAPLEN);
		}

		public int wirelen() {
			return getInt(FIELD_WIRELEN);
		}

	}

}
