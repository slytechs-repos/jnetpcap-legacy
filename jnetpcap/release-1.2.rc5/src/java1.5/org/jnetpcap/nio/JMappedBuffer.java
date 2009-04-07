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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Comparator;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JMappedBuffer implements JByteBuffer {

	private static class Entry {
		public final JByteBuffer buf;

		public final int end;

		public final int start;

		/**
		 * @param buf
		 * @param offset
		 * @param order
		 *          TODO
		 * @param end
		 */
		public Entry(JBuffer buf, int start, int length, int offset, ByteOrder order) {
			JBuffer b = new JBuffer(JMemory.Type.POINTER);
			b.peer(buf, offset, length);
			b.order(order);

			this.buf = b;
			this.start = start;
			this.end = start + length;
		}

		/**
		 * @param spanBuffer
		 */
		public Entry(SpanBuffer spanBuffer) {
			this.buf = spanBuffer;
			this.start = 0;
			this.end = 0;
		}
	}

	private static class JByteArrayBuffer implements JByteBuffer {
		protected byte[] data;

		protected ByteBuffer buf;

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getByte(int)
		 */
		public byte getByte(int index) {
			return data[index];
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getByteArray(int, byte[])
		 */
		public byte[] getByteArray(int index, byte[] array) {
			System.arraycopy(data, index, array, 0, array.length);

			return array;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getByteArray(int, int)
		 */
		public byte[] getByteArray(int index, int size) {
			return getByteArray(index, new byte[size]);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getDouble(int)
		 */
		public double getDouble(int index) {
			return buf.getDouble(index);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getFloat(int)
		 */
		public float getFloat(int index) {
			return buf.getFloat(index);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getInt(int)
		 */
		public int getInt(int index) {
			return buf.getInt(index);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getLong(int)
		 */
		public long getLong(int index) {
			return buf.getLong(index);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getShort(int)
		 */
		public short getShort(int index) {
			return buf.getShort(index);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getUByte(int)
		 */
		public int getUByte(int index) {
			byte b = data[index];

			return (b < 0) ? b + 256 : b;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getUInt(int)
		 */
		public long getUInt(int index) {
			int b = buf.getInt(index);

			return (b < 0) ? ((long) Integer.MAX_VALUE * 2L + 1L) + b : b;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#getUShort(int)
		 */
		public int getUShort(int index) {
			short b = buf.getShort(index);

			return (b < 0) ? ((int) Short.MAX_VALUE * 2 + 1) + b : b;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#order()
		 */
		public ByteOrder order() {
			return buf.order();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#order(java.nio.ByteOrder)
		 */
		public void order(ByteOrder order) {
			buf.order(order);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#setByte(int, byte)
		 */
		public void setByte(int index, byte value) {
			buf.put(index, value);
			commit();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#setByteArray(int, byte[])
		 */
		public void setByteArray(int index, byte[] array) {
			buf.put(array, index, array.length);
			commit();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#setDouble(int, double)
		 */
		public void setDouble(int index, double value) {
			buf.putDouble(index, value);
			commit();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#setFloat(int, float)
		 */
		public void setFloat(int index, float value) {
			buf.putFloat(index, value);
			commit();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#setInt(int, int)
		 */
		public void setInt(int index, int value) {
			buf.putInt(index, value);
			commit();
		}

		protected void commit() {
			// Empty
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#setLong(int, long)
		 */
		public void setLong(int index, long value) {
			buf.putLong(index, value);
			commit();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#setShort(int, short)
		 */
		public void setShort(int index, short value) {
			buf.putShort(index, value);
			commit();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#setUByte(int, int)
		 */
		public void setUByte(int index, int value) {
			buf.put(index, (byte) value);
			commit();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#setUInt(int, long)
		 */
		public void setUInt(int index, long value) {
			buf.putInt(index, (int) value);
			commit();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#setUShort(int, int)
		 */
		public void setUShort(int index, int value) {
			buf.putShort(index, (short) value);
			commit();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.nio.JByteBuffer#size()
		 */
		public int size() {
			return buf.limit() - buf.position();
		}

	}

	private static class SpanBuffer
	    extends JByteArrayBuffer {
		private JBuffer[] src = new JBuffer[2];

		private int offset;

		private int length;

		public void setDataRange(int offset, int length, JBuffer b1, JBuffer b2) {
			this.offset = offset;
			this.length = length;
			src[0] = b1;
			src[1] = b2;

			if (super.data == null || super.data.length < length) {
				super.data = new byte[length];
			}

			JBuffer s = src[0];
			for (int i = 0; i < length; i++) {
				if (i + offset >= s.size()) {
					s = src[1];
					offset = -i;
				}

				data[i] = s.getByte(i + offset);
			}
			
			super.buf = ByteBuffer.wrap(super.data);
		}

		protected void commit() {
			JBuffer s = src[0];
			for (int i = 0; i < length; i++) {
				if (i + offset >= s.size()) {
					s = src[1];
					offset = -i;
				}

				s.setByte(i + offset, data[i]);
			}

		}

	}

	private Entry last = null;

	private SpanBuffer spanb = new SpanBuffer();

	private Entry spane = new Entry(spanb);

	private SortedSet<Entry> mapped = new TreeSet<Entry>(new Comparator<Entry>() {

		public int compare(Entry o1, Entry o2) {
			return (int) (o1.start - o2.start);
		}

	});

	private int size;

	private ByteOrder order;

	public JMappedBuffer() {

	}

	public JMappedBuffer(int start, JBuffer... bufs) {
		add(start, bufs);
	}

	public JMappedBuffer(JBuffer... bufs) {
		add(0, bufs);
	}

	public int add(int start, JBuffer... bufs) {
		int o = start;

		for (JBuffer b : bufs) {
			o += add(b, o);
		}

		return o;
	}

	public int add(JBuffer buf, int start) {
		return add(buf, start, buf.size(), 0);
	}

	public int add(JBuffer buf, int start, int offset) {
		return add(buf, start, (buf.size() - offset), offset);
	}

	/**
	 * @param buf
	 * @param start
	 *          offset into the mapped buffer - starting sequence number
	 * @param length
	 *          length from the start into the buffer
	 * @param offset
	 *          offset into the supplied buffer
	 * @return
	 */
	public int add(JBuffer buf, int start, int length, int offset) {
		mapped.add(new Entry(buf, start, length, offset, order));

		size += length;

		return start + length;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getByte(int)
	 */
	public byte getByte(int index) {
		final Entry e = map(index, 1);
		return e.buf.getByte(index - e.start);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getByteArray(int, byte[])
	 */
	public byte[] getByteArray(int index, byte[] array) {
		final Entry e = map(index, array.length);
		return e.buf.getByteArray(index - e.start, array);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getByteArray(int, int)
	 */
	public byte[] getByteArray(int index, int size) {
		final Entry e = map(index, size);
		return e.buf.getByteArray(index - e.start, size);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getDouble(int)
	 */
	public double getDouble(int index) {
		final Entry e = map(index, 8);
		return e.buf.getDouble(index - e.start);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getFloat(int)
	 */
	public float getFloat(int index) {
		final Entry e = map(index, 4);
		return e.buf.getFloat(index - e.start);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getInt(int)
	 */
	public int getInt(int index) {
		final Entry e = map(index, 4);
		return e.buf.getInt(index - e.start);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getLong(int)
	 */
	public long getLong(int index) {
		final Entry e = map(index, 8);
		return e.buf.getLong(index - e.start);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getShort(int)
	 */
	public short getShort(int index) {
		final Entry e = map(index, 0);
		return e.buf.getShort(index - e.start);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getUByte(int)
	 */
	public int getUByte(int index) {
		final Entry e = map(index, 2);
		return e.buf.getUByte(index - e.start);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getUInt(int)
	 */
	public long getUInt(int index) {
		final Entry e = map(index, 4);
		return e.buf.getUInt(index - e.start);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#getUShort(int)
	 */
	public int getUShort(int index) {
		final Entry e = map(index, 2);
		return e.buf.getUShort(index - e.start);
	}

	private Entry map(int index, int len) {
		if (last != null && index >= last.start && index < last.end) {
			// Emptry
		} else {

			last = null;

			for (Entry e : mapped) {
				if (index >= e.start && index < e.end) {
					last = e;
					break;
				}

				/*
				 * Its a sorted set, we can exit the loop early if we are passed our
				 * sorted region in the set
				 */
				if (index < e.end) {
					break;
				}
			}
		}

		if (last == null) {
			throw new IndexOutOfBoundsException("no mapped buffer found for index "
			    + index);
		}

		/*
		 * Now check if we have a partial buffer match. A match that spans multiple
		 * buffers.
		 */
		if (index + len >= last.end) {
			/*
			 * We use a special buffer that copies the partial data out of source
			 * buffers into a special working buffer. We return that working buffer so
			 * our getter/setter methods can do their normal operation. Setter methods
			 * work a little differently since they also have to commit the values
			 * written to underlying buffers.
			 */
			spanb.setDataRange(index, len, (JBuffer) last.buf, (JBuffer) map(
			    last.end, 0).buf);

			return spane;

		} else {
			return last;
		}

	}

	public boolean remove(int offset) {
		Entry e = map(offset, 0);
		if (e == null) {
			return false;
		} else {
			if (last == e) {
				last = null;
			}

			size -= (e.end - e.start);
			return mapped.remove(e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#setByte(int, byte)
	 */
	public void setByte(int index, byte value) {
		final Entry e = map(index, 1);
		e.buf.setByte(index - e.start, value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#setByteArray(int, byte[])
	 */
	public void setByteArray(int index, byte[] array) {
		final Entry e = map(index, array.length);
		e.buf.setByteArray(index - e.start, array);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#setDouble(int, double)
	 */
	public void setDouble(int index, double value) {
		final Entry e = map(index, 8);
		e.buf.setDouble(index - e.start, value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#setFloat(int, float)
	 */
	public void setFloat(int index, float value) {
		final Entry e = map(index, 4);
		e.buf.setFloat(index - e.start, value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#setInt(int, int)
	 */
	public void setInt(int index, int value) {
		final Entry e = map(index, 4);
		e.buf.setInt(index - e.start, value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#setLong(int, long)
	 */
	public void setLong(int index, long value) {
		final Entry e = map(index, 8);
		e.buf.setLong(index - e.start, value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#setShort(int, short)
	 */
	public void setShort(int index, short value) {
		final Entry e = map(index, 2);
		e.buf.setShort(index - e.start, value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#setUByte(int, int)
	 */
	public void setUByte(int index, int value) {
		final Entry e = map(index, 1);
		e.buf.setUByte(index - e.start, value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#setUInt(int, long)
	 */
	public void setUInt(int index, long value) {
		final Entry e = map(index, 4);
		e.buf.setUInt(index - e.start, value);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#setUShort(int, int)
	 */
	public void setUShort(int index, int value) {
		final Entry e = map(index, 2);
		e.buf.setUShort(index - e.start, value);
	}

	public int size() {
		return this.size;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#order()
	 */
	public ByteOrder order() {
		return order;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.JByteBuffer#order(java.nio.ByteOrder)
	 */
	public void order(ByteOrder order) {
		this.order = order;

		for (Entry e : mapped) {
			e.buf.order(order);
		}
	}

}
