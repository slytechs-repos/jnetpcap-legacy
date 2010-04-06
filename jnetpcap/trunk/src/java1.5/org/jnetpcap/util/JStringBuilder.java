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
package org.jnetpcap.util;

/**
 * Subclassible delagate StringBuilder class. All the calls to this class are
 * delegated to a private instance of StringBuilder.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JStringBuilder implements Appendable {

	private final StringBuilder buffer;

	/**
	 * @see java.lang.StringBuilder#StringBuilder()
	 */
	public JStringBuilder() {
		this.buffer = new StringBuilder();
	}

	/**
	 * @param seq
	 * @see java.lang.StringBuilder#StringBuilder(java.lang.CharSequence)
	 */
	public JStringBuilder(CharSequence seq) {
		this.buffer = new StringBuilder(seq);
	}

	/**
	 * @param capacity
	 * @see java.lang.StringBuilder#StringBuilder(int)
	 */
	public JStringBuilder(int capacity) {
		this.buffer = new StringBuilder(capacity);
	}

	/**
	 * @param str
	 * @see java.lang.StringBuilder#StringBuilder(String)
	 */
	public JStringBuilder(String str) {
		this.buffer = new StringBuilder(str);

	}

	/**
	 * @param b
	 * @return
	 * @see java.lang.StringBuilder#append(boolean)
	 */
	public StringBuilder append(boolean b) {
		return this.buffer.append(b);
	}

	/**
	 * @param c
	 * @return
	 * @see java.lang.StringBuilder#append(char)
	 */
	public StringBuilder append(char c) {
		return this.buffer.append(c);
	}

	/**
	 * @param str
	 * @return
	 * @see java.lang.StringBuilder#append(char[])
	 */
	public StringBuilder append(char[] str) {
		return this.buffer.append(str);
	}

	/**
	 * @param str
	 * @param offset
	 * @param len
	 * @return
	 * @see java.lang.StringBuilder#append(char[], int, int)
	 */
	public StringBuilder append(char[] str, int offset, int len) {
		return this.buffer.append(str, offset, len);
	}

	/**
	 * @param s
	 * @return
	 * @see java.lang.StringBuilder#append(java.lang.CharSequence)
	 */
	public StringBuilder append(CharSequence s) {
		return this.buffer.append(s);
	}

	/**
	 * @param s
	 * @param start
	 * @param end
	 * @return
	 * @see java.lang.StringBuilder#append(java.lang.CharSequence, int, int)
	 */
	public StringBuilder append(CharSequence s, int start, int end) {
		return this.buffer.append(s, start, end);
	}

	/**
	 * @param d
	 * @return
	 * @see java.lang.StringBuilder#append(double)
	 */
	public StringBuilder append(double d) {
		return this.buffer.append(d);
	}

	/**
	 * @param f
	 * @return
	 * @see java.lang.StringBuilder#append(float)
	 */
	public StringBuilder append(float f) {
		return this.buffer.append(f);
	}

	/**
	 * @param i
	 * @return
	 * @see java.lang.StringBuilder#append(int)
	 */
	public StringBuilder append(int i) {
		return this.buffer.append(i);
	}

	/**
	 * @param lng
	 * @return
	 * @see java.lang.StringBuilder#append(long)
	 */
	public StringBuilder append(long lng) {
		return this.buffer.append(lng);
	}

	/**
	 * @param obj
	 * @return
	 * @see java.lang.StringBuilder#append(java.lang.Object)
	 */
	public StringBuilder append(Object obj) {
		return this.buffer.append(obj);
	}

	/**
	 * @param str
	 * @return
	 * @see java.lang.StringBuilder#append(java.lang.String)
	 */
	public StringBuilder append(String str) {
		return this.buffer.append(str);
	}

	/**
	 * @param sb
	 * @return
	 * @see java.lang.StringBuilder#append(java.lang.StringBuffer)
	 */
	public StringBuilder append(StringBuffer sb) {
		return this.buffer.append(sb);
	}

	/**
	 * @param codePoint
	 * @return
	 * @see java.lang.StringBuilder#appendCodePoint(int)
	 */
	public StringBuilder appendCodePoint(int codePoint) {
		return this.buffer.appendCodePoint(codePoint);
	}

	/**
	 * @return
	 * @see java.lang.AbstractStringBuilder#capacity()
	 */
	public int capacity() {
		return this.buffer.capacity();
	}

	/**
	 * @param index
	 * @return
	 * @see java.lang.AbstractStringBuilder#charAt(int)
	 */
	public char charAt(int index) {
		return this.buffer.charAt(index);
	}

	/**
	 * @param index
	 * @return
	 * @see java.lang.AbstractStringBuilder#codePointAt(int)
	 */
	public int codePointAt(int index) {
		return this.buffer.codePointAt(index);
	}

	/**
	 * @param index
	 * @return
	 * @see java.lang.AbstractStringBuilder#codePointBefore(int)
	 */
	public int codePointBefore(int index) {
		return this.buffer.codePointBefore(index);
	}

	/**
	 * @param beginIndex
	 * @param endIndex
	 * @return
	 * @see java.lang.AbstractStringBuilder#codePointCount(int, int)
	 */
	public int codePointCount(int beginIndex, int endIndex) {
		return this.buffer.codePointCount(beginIndex, endIndex);
	}

	/**
	 * @param start
	 * @param end
	 * @return
	 * @see java.lang.StringBuilder#delete(int, int)
	 */
	public StringBuilder delete(int start, int end) {
		return this.buffer.delete(start, end);
	}

	/**
	 * @param index
	 * @return
	 * @see java.lang.StringBuilder#deleteCharAt(int)
	 */
	public StringBuilder deleteCharAt(int index) {
		return this.buffer.deleteCharAt(index);
	}

	/**
	 * @param minimumCapacity
	 * @see java.lang.AbstractStringBuilder#ensureCapacity(int)
	 */
	public void ensureCapacity(int minimumCapacity) {
		this.buffer.ensureCapacity(minimumCapacity);
	}

	/**
	 * @param obj
	 * @return
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object obj) {
		return this.buffer.equals(obj);
	}

	/**
	 * @param srcBegin
	 * @param srcEnd
	 * @param dst
	 * @param dstBegin
	 * @see java.lang.AbstractStringBuilder#getChars(int, int, char[], int)
	 */
	public void getChars(int srcBegin, int srcEnd, char[] dst, int dstBegin) {
		this.buffer.getChars(srcBegin, srcEnd, dst, dstBegin);
	}

	/**
	 * @return
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return this.buffer.hashCode();
	}

	/**
	 * @param str
	 * @return
	 * @see java.lang.StringBuilder#indexOf(java.lang.String)
	 */
	public int indexOf(String str) {
		return this.buffer.indexOf(str);
	}

	/**
	 * @param str
	 * @param fromIndex
	 * @return
	 * @see java.lang.StringBuilder#indexOf(java.lang.String, int)
	 */
	public int indexOf(String str, int fromIndex) {
		return this.buffer.indexOf(str, fromIndex);
	}

	/**
	 * @param offset
	 * @param b
	 * @return
	 * @see java.lang.StringBuilder#insert(int, boolean)
	 */
	public StringBuilder insert(int offset, boolean b) {
		return this.buffer.insert(offset, b);
	}

	/**
	 * @param offset
	 * @param c
	 * @return
	 * @see java.lang.StringBuilder#insert(int, char)
	 */
	public StringBuilder insert(int offset, char c) {
		return this.buffer.insert(offset, c);
	}

	/**
	 * @param offset
	 * @param str
	 * @return
	 * @see java.lang.StringBuilder#insert(int, char[])
	 */
	public StringBuilder insert(int offset, char[] str) {
		return this.buffer.insert(offset, str);
	}

	/**
	 * @param index
	 * @param str
	 * @param offset
	 * @param len
	 * @return
	 * @see java.lang.StringBuilder#insert(int, char[], int, int)
	 */
	public StringBuilder insert(int index, char[] str, int offset, int len) {
		return this.buffer.insert(index, str, offset, len);
	}

	/**
	 * @param dstOffset
	 * @param s
	 * @return
	 * @see java.lang.StringBuilder#insert(int, java.lang.CharSequence)
	 */
	public StringBuilder insert(int dstOffset, CharSequence s) {
		return this.buffer.insert(dstOffset, s);
	}

	/**
	 * @param dstOffset
	 * @param s
	 * @param start
	 * @param end
	 * @return
	 * @see java.lang.StringBuilder#insert(int, java.lang.CharSequence, int, int)
	 */
	public StringBuilder insert(int dstOffset, CharSequence s, int start, int end) {
		return this.buffer.insert(dstOffset, s, start, end);
	}

	/**
	 * @param offset
	 * @param d
	 * @return
	 * @see java.lang.StringBuilder#insert(int, double)
	 */
	public StringBuilder insert(int offset, double d) {
		return this.buffer.insert(offset, d);
	}

	/**
	 * @param offset
	 * @param f
	 * @return
	 * @see java.lang.StringBuilder#insert(int, float)
	 */
	public StringBuilder insert(int offset, float f) {
		return this.buffer.insert(offset, f);
	}

	/**
	 * @param offset
	 * @param i
	 * @return
	 * @see java.lang.StringBuilder#insert(int, int)
	 */
	public StringBuilder insert(int offset, int i) {
		return this.buffer.insert(offset, i);
	}

	/**
	 * @param offset
	 * @param l
	 * @return
	 * @see java.lang.StringBuilder#insert(int, long)
	 */
	public StringBuilder insert(int offset, long l) {
		return this.buffer.insert(offset, l);
	}

	/**
	 * @param offset
	 * @param obj
	 * @return
	 * @see java.lang.StringBuilder#insert(int, java.lang.Object)
	 */
	public StringBuilder insert(int offset, Object obj) {
		return this.buffer.insert(offset, obj);
	}

	/**
	 * @param offset
	 * @param str
	 * @return
	 * @see java.lang.StringBuilder#insert(int, java.lang.String)
	 */
	public StringBuilder insert(int offset, String str) {
		return this.buffer.insert(offset, str);
	}

	/**
	 * @param str
	 * @return
	 * @see java.lang.StringBuilder#lastIndexOf(java.lang.String)
	 */
	public int lastIndexOf(String str) {
		return this.buffer.lastIndexOf(str);
	}

	/**
	 * @param str
	 * @param fromIndex
	 * @return
	 * @see java.lang.StringBuilder#lastIndexOf(java.lang.String, int)
	 */
	public int lastIndexOf(String str, int fromIndex) {
		return this.buffer.lastIndexOf(str, fromIndex);
	}

	/**
	 * @return
	 * @see java.lang.AbstractStringBuilder#length()
	 */
	public int length() {
		return this.buffer.length();
	}

	/**
	 * @param index
	 * @param codePointOffset
	 * @return
	 * @see java.lang.AbstractStringBuilder#offsetByCodePoints(int, int)
	 */
	public int offsetByCodePoints(int index, int codePointOffset) {
		return this.buffer.offsetByCodePoints(index, codePointOffset);
	}

	/**
	 * @param start
	 * @param end
	 * @param str
	 * @return
	 * @see java.lang.StringBuilder#replace(int, int, java.lang.String)
	 */
	public StringBuilder replace(int start, int end, String str) {
		return this.buffer.replace(start, end, str);
	}

	/**
	 * @return
	 * @see java.lang.StringBuilder#reverse()
	 */
	public StringBuilder reverse() {
		return this.buffer.reverse();
	}

	/**
	 * @param index
	 * @param ch
	 * @see java.lang.AbstractStringBuilder#setCharAt(int, char)
	 */
	public void setCharAt(int index, char ch) {
		this.buffer.setCharAt(index, ch);
	}

	/**
	 * @param newLength
	 * @see java.lang.AbstractStringBuilder#setLength(int)
	 */
	public void setLength(int newLength) {
		this.buffer.setLength(newLength);
	}

	/**
	 * @param start
	 * @param end
	 * @return
	 * @see java.lang.AbstractStringBuilder#subSequence(int, int)
	 */
	public CharSequence subSequence(int start, int end) {
		return this.buffer.subSequence(start, end);
	}

	/**
	 * @param start
	 * @return
	 * @see java.lang.AbstractStringBuilder#substring(int)
	 */
	public String substring(int start) {
		return this.buffer.substring(start);
	}

	/**
	 * @param start
	 * @param end
	 * @return
	 * @see java.lang.AbstractStringBuilder#substring(int, int)
	 */
	public String substring(int start, int end) {
		return this.buffer.substring(start, end);
	}

	/**
	 * @return
	 * @see java.lang.StringBuilder#toString()
	 */
	public String toString() {
		return this.buffer.toString();
	}

	/**
	 * @see java.lang.AbstractStringBuilder#trimToSize()
	 */
	public void trimToSize() {
		this.buffer.trimToSize();
	}

}
