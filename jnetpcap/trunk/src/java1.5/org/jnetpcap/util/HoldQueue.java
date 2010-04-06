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

import java.util.AbstractQueue;
import java.util.Comparator;
import java.util.Iterator;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class HoldQueue<T, C>
    extends
    AbstractQueue<T> implements Queue<T> {

	public static class HoldHandle<C> implements Comparable<C> {
		private final AtomicInteger ref = new AtomicInteger();

		private final Comparable<C> hold;

		private final HoldQueue<?, C> parent;

		/**
		 * @param hold
		 */
		public HoldHandle(HoldQueue<?, C> parent, Comparable<C> hold) {
			this.hold = hold;
			this.parent = parent;
		}

		public int release() {
			final int r = ref.decrementAndGet();
			if (r < 0) {
				throw new IllegalStateException("invalid hold-handle");
			}

			if (r == 0) {
				parent.release(this);
			}

			return r;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Comparable#compareTo(java.lang.Object)
		 */
		public int compareTo(C o) {
			return hold.compareTo(o);
		}
	}

	private final PriorityQueue<HoldHandle<C>> handles =
	    new PriorityQueue<HoldHandle<C>>();

	private final Queue<T> hidden;

	private final Queue<T> exposed;

	private HoldHandle<C> hold;

	private final Comparator<T> comparator;

	protected HoldQueue(
	    final Queue<T> hidden,
	    final Queue<T> exposed,
	    Comparator<T> comparator) {
		this.hidden = hidden;
		this.exposed = exposed;
		this.comparator = comparator;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.util.AbstractCollection#iterator()
	 */
	@Override
	public Iterator<T> iterator() {
		return exposed.iterator();
	}

	/**
	 * @param hold
	 */
	private void release(HoldHandle<C> handle) {
		handles.remove(handle);

		this.hold = (handles.isEmpty()) ? null : handles.peek();

//		while (handle.compareTo(hidden.peek()) > 0) {
//			exposed.offer(hidden.poll());
//		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.util.AbstractCollection#size()
	 */
	@Override
	public int size() {
		return exposed.size();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.util.Queue#offer(java.lang.Object)
	 */
	public boolean offer(T o) {
		if (hold == null) {
			exposed.offer(o);
		}
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.util.Queue#peek()
	 */
	public T peek() {
		return exposed.peek();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.util.Queue#poll()
	 */
	public T poll() {
		return exposed.poll();
	}

}
