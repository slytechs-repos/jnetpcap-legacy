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

// TODO: Auto-generated Javadoc
/**
 * The Class BlockingQueuePump.
 * 
 * @param <T>
 *          the generic type
 */
public abstract class BlockingQueuePump<T> implements BlockingQueue<T> {

	/** The name. */
	private final String name;

	/** The queue. */
	private final BlockingQueue<T> queue;

	/** The thread. */
	private final AtomicReference<Thread> thread = new AtomicReference<Thread>();

	/**
	 * Instantiates a new blocking queue pump.
	 * 
	 * @param name
	 *          the name
	 */
	public BlockingQueuePump(String name) {
		this.queue = new LinkedBlockingQueue<T>();
		this.name = name;

		start();
	}

	/**
	 * Instantiates a new blocking queue pump.
	 * 
	 * @param name
	 *          the name
	 * @param capacity
	 *          the capacity
	 */
	public BlockingQueuePump(String name, int capacity) {
		this.queue = new ArrayBlockingQueue<T>(capacity);
		this.name = name;

		start();
	}

	/* (non-Javadoc)
	 * @see java.util.concurrent.BlockingQueue#add(java.lang.Object)
	 */
	public boolean add(T o) {
		return this.queue.add(o);
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#addAll(java.util.Collection)
	 */
	public boolean addAll(Collection<? extends T> c) {
		return this.queue.addAll(c);
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#clear()
	 */
	public void clear() {
		this.queue.clear();
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#contains(java.lang.Object)
	 */
	public boolean contains(Object o) {
		return this.queue.contains(o);
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#containsAll(java.util.Collection)
	 */
	public boolean containsAll(Collection<?> c) {
		return this.queue.containsAll(c);
	}

	/**
	 * Dispatch.
	 * 
	 * @param data
	 *          the data
	 */
	protected abstract void dispatch(T data);

	/* (non-Javadoc)
	 * @see java.util.concurrent.BlockingQueue#drainTo(java.util.Collection)
	 */
	public int drainTo(Collection<? super T> c) {
		return this.queue.drainTo(c);
	}

	/* (non-Javadoc)
	 * @see java.util.concurrent.BlockingQueue#drainTo(java.util.Collection, int)
	 */
	public int drainTo(Collection<? super T> c, int maxElements) {
		return this.queue.drainTo(c, maxElements);
	}

	/* (non-Javadoc)
	 * @see java.util.Queue#element()
	 */
	public T element() {
		return this.queue.element();
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object o) {
		return this.queue.equals(o);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return this.queue.hashCode();
	}

	/**
	 * Checks if is alive.
	 * 
	 * @return true, if is alive
	 */
	public boolean isAlive() {
		return thread.get() != null && thread.get().isAlive();
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#isEmpty()
	 */
	public boolean isEmpty() {
		return this.queue.isEmpty();
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#iterator()
	 */
	public Iterator<T> iterator() {
		return this.queue.iterator();
	}

	/* (non-Javadoc)
	 * @see java.util.concurrent.BlockingQueue#offer(java.lang.Object)
	 */
	public boolean offer(T o) {
		return this.queue.offer(o);
	}

	/* (non-Javadoc)
	 * @see java.util.concurrent.BlockingQueue#offer(java.lang.Object, long, java.util.concurrent.TimeUnit)
	 */
	public boolean offer(T o, long timeout, TimeUnit unit)
	    throws InterruptedException {
		return this.queue.offer(o, timeout, unit);
	}

	/* (non-Javadoc)
	 * @see java.util.Queue#peek()
	 */
	public T peek() {
		return this.queue.peek();
	}

	/* (non-Javadoc)
	 * @see java.util.Queue#poll()
	 */
	public T poll() {
		return this.queue.poll();
	}

	/* (non-Javadoc)
	 * @see java.util.concurrent.BlockingQueue#poll(long, java.util.concurrent.TimeUnit)
	 */
	public T poll(long timeout, TimeUnit unit) throws InterruptedException {
		return this.queue.poll(timeout, unit);
	}

	/* (non-Javadoc)
	 * @see java.util.concurrent.BlockingQueue#put(java.lang.Object)
	 */
	public void put(T o) throws InterruptedException {
		this.queue.put(o);
	}

	/* (non-Javadoc)
	 * @see java.util.concurrent.BlockingQueue#remainingCapacity()
	 */
	public int remainingCapacity() {
		return this.queue.remainingCapacity();
	}

	/* (non-Javadoc)
	 * @see java.util.Queue#remove()
	 */
	public T remove() {
		return this.queue.remove();
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#remove(java.lang.Object)
	 */
	public boolean remove(Object o) {
		return this.queue.remove(o);
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#removeAll(java.util.Collection)
	 */
	public boolean removeAll(Collection<?> c) {
		return this.queue.removeAll(c);
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#retainAll(java.util.Collection)
	 */
	public boolean retainAll(Collection<?> c) {
		return this.queue.retainAll(c);
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#size()
	 */
	public int size() {
		return this.queue.size();
	}

	/** The dispatch queue. */
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

	/**
	 * Start.
	 */
	public void start() {

		if (thread.get() != null) {
			throw new IllegalStateException(name + " thread unexpected termination");
		}

		thread.set(new Thread(dispatchQueue, name));
		thread.get().setDaemon(true);
		thread.get().start();
	}

	/**
	 * Stop.
	 */
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

	/* (non-Javadoc)
	 * @see java.util.concurrent.BlockingQueue#take()
	 */
	public T take() throws InterruptedException {
		return this.queue.take();
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#toArray()
	 */
	public Object[] toArray() {
		return this.queue.toArray();
	}

	/* (non-Javadoc)
	 * @see java.util.Collection#toArray(T[])
	 */
	public <Q> Q[] toArray(Q[] a) {
		return this.queue.toArray(a);
	}
}
