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
package org.jnetpcap.bugs;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import junit.framework.TestCase;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory.Type;

/**
 * @author Sly Technologies, Inc.
 * 
 */
public class Bug3401623_DisposableGC extends TestCase {

	private static final PrintStream out = System.out;

	private static final int THREAD_COUNT = 30;
	private static final long SLEEP = 1 * 60 * 60 * 1000;

	protected static final int QUEUE_SIZE = 100;

	private ThreadGroup group;
	private final List<Thread> threads = new ArrayList<Thread>();

	@Override
	public void setUp() {
		disposeThreads();
	}

	@Override
	public void tearDown() {
		disposeThreads();
	}

	private void disposeThreads() {

		if (group != null) {
			group.stop();
			while (group.activeCount() != 0) {
				try {
					Thread.sleep(1);
				} catch (InterruptedException e) {

				}
			}
		}

		threads.clear();

		if (group != null) {
			group.destroy();
			group = null;
		}
	}

	private void setupThreads(final String name, final int count, Runnable code) {

		group = new ThreadGroup(name);

		for (int i = 0; i < count; i++) {
			final String label = String.format("%s#%02d", name, i);
			Thread thread = new Thread(group, code, label);
			out.printf("Setup %s\n", thread.getName());

			threads.add(thread);
		}

	}

	private void startThreads() {
		for (Thread thread : threads) {
			thread.start();
			out.printf("Started %s\n", thread.getName());
		}

	}

	public void test1() throws InterruptedException {

		final AtomicInteger counter = new AtomicInteger();

		Runnable code = new Runnable() {

			final BlockingQueue<JBuffer> queue = new ArrayBlockingQueue<JBuffer>(
					QUEUE_SIZE);

			final JBuffer buf2 = new JBuffer(Type.POINTER);

			public void run() {

				while (true) {
					for (int i = 0; i < 10; i++) {
						try {
							// out.printf("Offering %s:\n", Thread.currentThread().getName());
							queue.offer(new JBuffer(1024), 1, TimeUnit.MILLISECONDS);
							Thread.yield();
						} catch (InterruptedException e) {
							break;
						}
					}

					while (queue.isEmpty() == false) {

						try {
							// out.printf("Polling %s:\n", Thread.currentThread().getName());
							JBuffer b = queue.poll(1, TimeUnit.MILLISECONDS);

							if (b == null) {
								continue;
							}

							b.peer(buf2);

							int c = counter.incrementAndGet();

							if (c % 3 == 1) {
								queue.offer(b);
							}

							if ((c % 1000000) == 0) {
								out.printf("%s: %d\n", Thread.currentThread().getName(), c);
							}
						} catch (InterruptedException e) {
							break;
						}

						Thread.yield();
					}
				}
			}
		};

		setupThreads("test1", THREAD_COUNT, code);

		startThreads();

		Thread.sleep(SLEEP);
	}
}
