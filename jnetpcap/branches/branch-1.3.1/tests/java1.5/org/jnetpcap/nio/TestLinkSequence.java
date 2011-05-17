/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011 Sly Technologies, Inc.
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

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

/**
 * @author Sly Technologies, Inc.
 * 
 */
public class TestLinkSequence extends TestCase {

	public static class DefaultLink<T> implements Link<T> {

		public Link<T> next;
		public Link<T> prev;
		public LinkSequence<T> seq;
		public final T data;

		public DefaultLink(T data) {
			this.data = data;
		}

		/**
		 * @return
		 * @see org.jnetpcap.nio.Link#linkNext()
		 */
		public Link<T> linkNext() {
			return next;
		}

		/**
		 * @param l
		 * @see org.jnetpcap.nio.Link#linkNext(org.jnetpcap.nio.Link)
		 */
		public void linkNext(Link<T> l) {
			this.next = l;

		}

		/**
		 * @return
		 * @see org.jnetpcap.nio.Link#linkPrev()
		 */
		public Link<T> linkPrev() {
			return prev;
		}

		/**
		 * @param l
		 * @see org.jnetpcap.nio.Link#linkPrev(org.jnetpcap.nio.Link)
		 */
		public void linkPrev(Link<T> l) {
			this.prev = l;

		}

		/**
		 * @return
		 * @see org.jnetpcap.nio.Link#linkElement()
		 */
		public T linkElement() {
			return data;
		}

		/**
		 * @return
		 * @see org.jnetpcap.nio.Link#linkCollection()
		 */
		public LinkSequence<T> linkCollection() {
			return seq;
		}

		/**
		 * @param c
		 * @see org.jnetpcap.nio.Link#linkCollection(org.jnetpcap.nio.LinkSequence)
		 */
		public void linkCollection(LinkSequence<T> c) {
			this.seq = c;

		}

		@Override
		public String toString() {
			return String.format("@%04X[@%04X,@%04X]",
					(short) hashCode(),
					(prev == null) ? 0 : (short) prev.hashCode(),
					(next == null) ? 0 : (short) next.hashCode());
		}
	}

	public void testAddLinkToSequence() {
		LinkSequence<String> seq = new LinkSequence<String>();

		Link<String> l1 = new DefaultLink<String>("l1");
		Link<String> l2 = new DefaultLink<String>("l2");

		// System.out.println(seq.toString());
		seq.add(l1);
		// System.out.println(seq.toString());
		seq.add(l2);
		// System.out.println(seq.toString());

		assertEquals(l1.linkNext(), l2);
		assertEquals(l2.linkPrev(), l1);

		seq.remove(l2);
		// System.out.println(seq.toString());
		seq.remove(l1);
		// System.out.println(seq.toString());
	}

	public void testRemoveLinkFromSequence() {
		final int COUNT = 10;
		List<Link<String>> list = new ArrayList<Link<String>>(COUNT);
		LinkSequence<String> seq = new LinkSequence<String>();

		for (int i = 0; i < COUNT; i++) {
			Link<String> l = new DefaultLink<String>(Integer.toString(i));
			seq.add(l);
			list.add(l);
		}
		assertEquals(COUNT, seq.size());

		for (Link<String> l : list) {
			seq.remove(l);
		}

		assertEquals(0, seq.size());
	}

}
