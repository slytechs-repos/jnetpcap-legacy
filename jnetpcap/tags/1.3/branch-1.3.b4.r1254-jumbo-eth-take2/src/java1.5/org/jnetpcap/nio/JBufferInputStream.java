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

import java.io.IOException;
import java.io.InputStream;

// TODO: Auto-generated Javadoc
/**
 * The Class JBufferInputStream.
 */
public class JBufferInputStream
    extends
    InputStream {

	/** The in. */
	private final JBuffer in;

	/** The position. */
	private int position;

	/** The end. */
	private final int end;

	/** The mark. */
	private int mark = -1;

	/**
	 * Instantiates a new j buffer input stream.
	 * 
	 * @param in
	 *          the in
	 */
	public JBufferInputStream(JBuffer in) {
		this(in, 0, in.size());
	}

	/**
	 * Instantiates a new j buffer input stream.
	 * 
	 * @param in
	 *          the in
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
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

	/* (non-Javadoc)
	 * @see java.io.InputStream#read()
	 */
	@Override
	public int read() throws IOException {
		if (position == end) {
			return -1;
		}

		return in.getUByte(position++);
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#available()
	 */
	@Override
	public int available() throws IOException {
		return end - position;
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#close()
	 */
	@Override
	public void close() throws IOException {
		position = end;
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#read(byte[], int, int)
	 */
	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		final int length = max(len);

		in.getByteArray(position, b, off, length);

		return length;
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#read(byte[])
	 */
	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#skip(long)
	 */
	@Override
	public long skip(long n) throws IOException {
		long length = max((int) n);
		position += max((int) n);

		return length;
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#mark(int)
	 */
	@Override
	public synchronized void mark(int readlimit) {
		this.mark = position;
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#markSupported()
	 */
	@Override
	public boolean markSupported() {
		return true;
	}

	/* (non-Javadoc)
	 * @see java.io.InputStream#reset()
	 */
	@Override
	public synchronized void reset() throws IOException {
		if (mark != -1) {
			position = mark;
			mark = -1;
		}
	}

	/**
	 * Max.
	 * 
	 * @param len
	 *          the len
	 * @return the int
	 */
	private int max(int len) {
		final int available = end - position;
		final int max = (len > available) ? available : len;

		return max;
	}
}
