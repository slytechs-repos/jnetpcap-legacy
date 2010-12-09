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
package org.jnetpcap.util;

// TODO: Auto-generated Javadoc
/**
 * The Class JStringBuilder.
 */
public class JStringBuilder implements Appendable {

	/** The buffer. */
	private final StringBuilder buffer;

	/**
	 * Instantiates a new j string builder.
	 */
	public JStringBuilder() {
		this.buffer = new StringBuilder();
	}

	/**
	 * Instantiates a new j string builder.
	 * 
	 * @param seq
	 *          the seq
	 */
	public JStringBuilder(CharSequence seq) {
		this.buffer = new StringBuilder(seq);
	}

	/**
	 * Instantiates a new j string builder.
	 * 
	 * @param capacity
	 *          the capacity
	 */
	public JStringBuilder(int capacity) {
		this.buffer = new StringBuilder(capacity);
	}

	/**
	 * Instantiates a new j string builder.
	 * 
	 * @param str
	 *          the str
	 */
	public JStringBuilder(String str) {
		this.buffer = new StringBuilder(str);

	}

	/**
	 * Append.
	 * 
	 * @param b
	 *          the b
	 * @return the string builder
	 */
	public StringBuilder append(boolean b) {
		return this.buffer.append(b);
	}

	/* (non-Javadoc)
	 * @see java.lang.Appendable#append(char)
	 */
	public StringBuilder append(char c) {
		return this.buffer.append(c);
	}

	/**
	 * Append.
	 * 
	 * @param str
	 *          the str
	 * @return the string builder
	 */
	public StringBuilder append(char[] str) {
		return this.buffer.append(str);
	}

	/**
	 * Append.
	 * 
	 * @param str
	 *          the str
	 * @param offset
	 *          the offset
	 * @param len
	 *          the len
	 * @return the string builder
	 */
	public StringBuilder append(char[] str, int offset, int len) {
		return this.buffer.append(str, offset, len);
	}

	/* (non-Javadoc)
	 * @see java.lang.Appendable#append(java.lang.CharSequence)
	 */
	public StringBuilder append(CharSequence s) {
		return this.buffer.append(s);
	}

	/* (non-Javadoc)
	 * @see java.lang.Appendable#append(java.lang.CharSequence, int, int)
	 */
	public StringBuilder append(CharSequence s, int start, int end) {
		return this.buffer.append(s, start, end);
	}

	/**
	 * Append.
	 * 
	 * @param d
	 *          the d
	 * @return the string builder
	 */
	public StringBuilder append(double d) {
		return this.buffer.append(d);
	}

	/**
	 * Append.
	 * 
	 * @param f
	 *          the f
	 * @return the string builder
	 */
	public StringBuilder append(float f) {
		return this.buffer.append(f);
	}

	/**
	 * Append.
	 * 
	 * @param i
	 *          the i
	 * @return the string builder
	 */
	public StringBuilder append(int i) {
		return this.buffer.append(i);
	}

	/**
	 * Append.
	 * 
	 * @param lng
	 *          the lng
	 * @return the string builder
	 */
	public StringBuilder append(long lng) {
		return this.buffer.append(lng);
	}

	/**
	 * Append.
	 * 
	 * @param obj
	 *          the obj
	 * @return the string builder
	 */
	public StringBuilder append(Object obj) {
		return this.buffer.append(obj);
	}

	/**
	 * Append.
	 * 
	 * @param str
	 *          the str
	 * @return the string builder
	 */
	public StringBuilder append(String str) {
		return this.buffer.append(str);
	}

	/**
	 * Append.
	 * 
	 * @param sb
	 *          the sb
	 * @return the string builder
	 */
	public StringBuilder append(StringBuffer sb) {
		return this.buffer.append(sb);
	}

	/**
	 * Append code point.
	 * 
	 * @param codePoint
	 *          the code point
	 * @return the string builder
	 */
	public StringBuilder appendCodePoint(int codePoint) {
		return this.buffer.appendCodePoint(codePoint);
	}

	/**
	 * Capacity.
	 * 
	 * @return the int
	 */
	public int capacity() {
		return this.buffer.capacity();
	}

	/**
	 * Char at.
	 * 
	 * @param index
	 *          the index
	 * @return the char
	 */
	public char charAt(int index) {
		return this.buffer.charAt(index);
	}

	/**
	 * Code point at.
	 * 
	 * @param index
	 *          the index
	 * @return the int
	 */
	public int codePointAt(int index) {
		return this.buffer.codePointAt(index);
	}

	/**
	 * Code point before.
	 * 
	 * @param index
	 *          the index
	 * @return the int
	 */
	public int codePointBefore(int index) {
		return this.buffer.codePointBefore(index);
	}

	/**
	 * Code point count.
	 * 
	 * @param beginIndex
	 *          the begin index
	 * @param endIndex
	 *          the end index
	 * @return the int
	 */
	public int codePointCount(int beginIndex, int endIndex) {
		return this.buffer.codePointCount(beginIndex, endIndex);
	}

	/**
	 * Delete.
	 * 
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @return the string builder
	 */
	public StringBuilder delete(int start, int end) {
		return this.buffer.delete(start, end);
	}

	/**
	 * Delete char at.
	 * 
	 * @param index
	 *          the index
	 * @return the string builder
	 */
	public StringBuilder deleteCharAt(int index) {
		return this.buffer.deleteCharAt(index);
	}

	/**
	 * Ensure capacity.
	 * 
	 * @param minimumCapacity
	 *          the minimum capacity
	 */
	public void ensureCapacity(int minimumCapacity) {
		this.buffer.ensureCapacity(minimumCapacity);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object obj) {
		return this.buffer.equals(obj);
	}

	/**
	 * Gets the chars.
	 * 
	 * @param srcBegin
	 *          the src begin
	 * @param srcEnd
	 *          the src end
	 * @param dst
	 *          the dst
	 * @param dstBegin
	 *          the dst begin
	 */
	public void getChars(int srcBegin, int srcEnd, char[] dst, int dstBegin) {
		this.buffer.getChars(srcBegin, srcEnd, dst, dstBegin);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return this.buffer.hashCode();
	}

	/**
	 * Index of.
	 * 
	 * @param str
	 *          the str
	 * @return the int
	 */
	public int indexOf(String str) {
		return this.buffer.indexOf(str);
	}

	/**
	 * Index of.
	 * 
	 * @param str
	 *          the str
	 * @param fromIndex
	 *          the from index
	 * @return the int
	 */
	public int indexOf(String str, int fromIndex) {
		return this.buffer.indexOf(str, fromIndex);
	}

	/**
	 * Insert.
	 * 
	 * @param offset
	 *          the offset
	 * @param b
	 *          the b
	 * @return the string builder
	 */
	public StringBuilder insert(int offset, boolean b) {
		return this.buffer.insert(offset, b);
	}

	/**
	 * Insert.
	 * 
	 * @param offset
	 *          the offset
	 * @param c
	 *          the c
	 * @return the string builder
	 */
	public StringBuilder insert(int offset, char c) {
		return this.buffer.insert(offset, c);
	}

	/**
	 * Insert.
	 * 
	 * @param offset
	 *          the offset
	 * @param str
	 *          the str
	 * @return the string builder
	 */
	public StringBuilder insert(int offset, char[] str) {
		return this.buffer.insert(offset, str);
	}

	/**
	 * Insert.
	 * 
	 * @param index
	 *          the index
	 * @param str
	 *          the str
	 * @param offset
	 *          the offset
	 * @param len
	 *          the len
	 * @return the string builder
	 */
	public StringBuilder insert(int index, char[] str, int offset, int len) {
		return this.buffer.insert(index, str, offset, len);
	}

	/**
	 * Insert.
	 * 
	 * @param dstOffset
	 *          the dst offset
	 * @param s
	 *          the s
	 * @return the string builder
	 */
	public StringBuilder insert(int dstOffset, CharSequence s) {
		return this.buffer.insert(dstOffset, s);
	}

	/**
	 * Insert.
	 * 
	 * @param dstOffset
	 *          the dst offset
	 * @param s
	 *          the s
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @return the string builder
	 */
	public StringBuilder insert(int dstOffset, CharSequence s, int start, int end) {
		return this.buffer.insert(dstOffset, s, start, end);
	}

	/**
	 * Insert.
	 * 
	 * @param offset
	 *          the offset
	 * @param d
	 *          the d
	 * @return the string builder
	 */
	public StringBuilder insert(int offset, double d) {
		return this.buffer.insert(offset, d);
	}

	/**
	 * Insert.
	 * 
	 * @param offset
	 *          the offset
	 * @param f
	 *          the f
	 * @return the string builder
	 */
	public StringBuilder insert(int offset, float f) {
		return this.buffer.insert(offset, f);
	}

	/**
	 * Insert.
	 * 
	 * @param offset
	 *          the offset
	 * @param i
	 *          the i
	 * @return the string builder
	 */
	public StringBuilder insert(int offset, int i) {
		return this.buffer.insert(offset, i);
	}

	/**
	 * Insert.
	 * 
	 * @param offset
	 *          the offset
	 * @param l
	 *          the l
	 * @return the string builder
	 */
	public StringBuilder insert(int offset, long l) {
		return this.buffer.insert(offset, l);
	}

	/**
	 * Insert.
	 * 
	 * @param offset
	 *          the offset
	 * @param obj
	 *          the obj
	 * @return the string builder
	 */
	public StringBuilder insert(int offset, Object obj) {
		return this.buffer.insert(offset, obj);
	}

	/**
	 * Insert.
	 * 
	 * @param offset
	 *          the offset
	 * @param str
	 *          the str
	 * @return the string builder
	 */
	public StringBuilder insert(int offset, String str) {
		return this.buffer.insert(offset, str);
	}

	/**
	 * Last index of.
	 * 
	 * @param str
	 *          the str
	 * @return the int
	 */
	public int lastIndexOf(String str) {
		return this.buffer.lastIndexOf(str);
	}

	/**
	 * Last index of.
	 * 
	 * @param str
	 *          the str
	 * @param fromIndex
	 *          the from index
	 * @return the int
	 */
	public int lastIndexOf(String str, int fromIndex) {
		return this.buffer.lastIndexOf(str, fromIndex);
	}

	/**
	 * Length.
	 * 
	 * @return the int
	 */
	public int length() {
		return this.buffer.length();
	}

	/**
	 * Offset by code points.
	 * 
	 * @param index
	 *          the index
	 * @param codePointOffset
	 *          the code point offset
	 * @return the int
	 */
	public int offsetByCodePoints(int index, int codePointOffset) {
		return this.buffer.offsetByCodePoints(index, codePointOffset);
	}

	/**
	 * Replace.
	 * 
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @param str
	 *          the str
	 * @return the string builder
	 */
	public StringBuilder replace(int start, int end, String str) {
		return this.buffer.replace(start, end, str);
	}

	/**
	 * Reverse.
	 * 
	 * @return the string builder
	 */
	public StringBuilder reverse() {
		return this.buffer.reverse();
	}

	/**
	 * Sets the char at.
	 * 
	 * @param index
	 *          the index
	 * @param ch
	 *          the ch
	 */
	public void setCharAt(int index, char ch) {
		this.buffer.setCharAt(index, ch);
	}

	/**
	 * Sets the length.
	 * 
	 * @param newLength
	 *          the new length
	 */
	public void setLength(int newLength) {
		this.buffer.setLength(newLength);
	}

	/**
	 * Sub sequence.
	 * 
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @return the char sequence
	 */
	public CharSequence subSequence(int start, int end) {
		return this.buffer.subSequence(start, end);
	}

	/**
	 * Substring.
	 * 
	 * @param start
	 *          the start
	 * @return the string
	 */
	public String substring(int start) {
		return this.buffer.substring(start);
	}

	/**
	 * Substring.
	 * 
	 * @param start
	 *          the start
	 * @param end
	 *          the end
	 * @return the string
	 */
	public String substring(int start, int end) {
		return this.buffer.substring(start, end);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return this.buffer.toString();
	}

	/**
	 * Trim to size.
	 */
	public void trimToSize() {
		this.buffer.trimToSize();
	}

}
