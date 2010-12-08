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

import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class BlockingQueuePump<T> implements BlockingQueue<T> {

	private final String name;

	private final BlockingQueue<T> queue;

	private final AtomicReference<Thread> thread = new AtomicReference<Thread>();

	/**
	 * Unlimited capacity queue.
	 * 
	 * @param name
	 *          name to use for the worker thread
	 */
	public BlockingQueuePump(String name) {
		this.queue = new LinkedBlockingQueue<T>();
		this.name = name;

		start();
	}

	/**
	 * A limited in capacity queue.
	 * 
	 * @param name
	 *          name to use for the workder thread
	 * @param capacity
	 *          maximum capacity of the queue
	 */
	public BlockingQueuePump(String name, int capacity) {
		this.queue = new ArrayBlockingQueue<T>(capacity);
		this.name = name;

		start();
	}

	public boolean add(T o) {
		return this.queue.add(o);
	}

	public boolean addAll(Collection<? extends T> c) {
		return this.queue.addAll(c);
	}

	public void clear() {
		this.queue.clear();
	}

	public boolean contains(Object o) {
		return this.queue.contains(o);
	}

	public boolean containsAll(Collection<?> c) {
		return this.queue.containsAll(c);
	}

	protected abstract void dispatch(T data);

	public int drainTo(Collection<? super T> c) {
		return this.queue.drainTo(c);
	}

	public int drainTo(Collection<? super T> c, int maxElements) {
		return this.queue.drainTo(c, maxElements);
	}

	public T element() {
		return this.queue.element();
	}

	public boolean equals(Object o) {
		return this.queue.equals(o);
	}

	public int hashCode() {
		return this.queue.hashCode();
	}

	public boolean isAlive() {
		return thread.get() != null && thread.get().isAlive();
	}

	public boolean isEmpty() {
		return this.queue.isEmpty();
	}

	public Iterator<T> iterator() {
		return this.queue.iterator();
	}

	public boolean offer(T o) {
		return this.queue.offer(o);
	}

	public boolean offer(T o, long timeout, TimeUnit unit)
	    throws InterruptedException {
		return this.queue.offer(o, timeout, unit);
	}

	public T peek() {
		return this.queue.peek();
	}

	public T poll() {
		return this.queue.poll();
	}

	public T poll(long timeout, TimeUnit unit) throws InterruptedException {
		return this.queue.poll(timeout, unit);
	}

	public void put(T o) throws InterruptedException {
		this.queue.put(o);
	}

	public int remainingCapacity() {
		return this.queue.remainingCapacity();
	}

	public T remove() {
		return this.queue.remove();
	}

	public boolean remove(Object o) {
		return this.queue.remove(o);
	}

	public boolean removeAll(Collection<?> c) {
		return this.queue.removeAll(c);
	}

	public boolean retainAll(Collection<?> c) {
		return this.queue.retainAll(c);
	}

	public int size() {
		return this.queue.size();
	}

	public Runnable dispatchQueue = new Runnable() {

		public void run() {
			try {
				while (thread.get() != null) {
					dispatch(take());
				}

				if (thread.get() != null) {
					throw new IllegalStateException(name
					    + " thread unexpected termination");
				}

			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} finally {
				thread.set(null);
			}
		}

	};

	public void start() {

		if (thread.get() != null) {
			throw new IllegalStateException(name + " thread unexpected termination");
		}

		thread.set(new Thread(dispatchQueue, name));
		thread.get().setDaemon(true);
		thread.get().start();
	}

	public void stop() {
		if (thread.get() == null || thread.get().isAlive() == false) {
			thread.set(null);
			return;
		}

		synchronized (thread.get()) {
			try {
				thread.wait();
			} catch (InterruptedException e) {
			} finally {
				this.thread.set(null);
			}
		}
	}

	public T take() throws InterruptedException {
		return this.queue.take();
	}

	public Object[] toArray() {
		return this.queue.toArray();
	}

	public <Q> Q[] toArray(Q[] a) {
		return this.queue.toArray(a);
	}
}
