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

import java.io.IOException;
import java.io.InputStream;

/**
 * IO InputStream class that reads data out of a JBuffer. This implementation
 * supports all methods efficiently, including bulk transfers and the optional
 * mark operation.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JBufferInputStream
    extends
    InputStream {

	private final JBuffer in;

	private int position;

	private final int end;

	private int mark = -1;

	public JBufferInputStream(JBuffer in) {
		this(in, 0, in.size());
	}

	/**
	 * @param in
	 * @param offset
	 * @param length
	 */
	public JBufferInputStream(JBuffer in, int offset, int length) {
		/*
		 * Make sure the requested length is not bigger then our buffer. We can't
		 * use max(), because position and end haven't been initialized yet
		 */
		length = (offset + length > in.size()) ? in.size() - offset : length;

		this.in = in;
		this.position = offset;
		this.end = offset + length;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.InputStream#read()
	 */
	@Override
	public int read() throws IOException {
		if (position == end) {
			return -1;
		}

		return in.getUByte(position++);
	}

	@Override
	public int available() throws IOException {
		return end - position;
	}

	@Override
	public void close() throws IOException {
		position = end;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		final int length = max(len);

		in.getByteArray(position, b, off, length);

		return length;
	}

	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	@Override
	public long skip(long n) throws IOException {
		long length = max((int) n);
		position += max((int) n);

		return length;
	}

	@Override
	public synchronized void mark(int readlimit) {
		this.mark = position;
	}

	@Override
	public boolean markSupported() {
		return true;
	}

	@Override
	public synchronized void reset() throws IOException {
		if (mark != -1) {
			position = mark;
			mark = -1;
		}
	}

	/**
	 * Calculate the maximum length that can be read out of the buffer based on
	 * the length requested. If the requested length is greater then what can be
	 * read out of the buffer, then this method returns just the available length.
	 * 
	 * @param len
	 *          checks if len bytes are aviable for reading
	 * @return number of bytes available for reading, upto the maximum of the
	 *         length requested
	 */
	private int max(int len) {
		final int available = end - position;
		final int max = (len > available) ? available : len;

		return max;
	}
}
