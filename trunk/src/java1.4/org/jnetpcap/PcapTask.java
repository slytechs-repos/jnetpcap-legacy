/**
 * $Id$ Copyright (C) 2008 Sly Technologies, Inc. This library is free software;
 * you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package org.jnetpcap;

/**
 * A pcap background task handle. This provides status and control over the
 * background loop.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class PcapTask implements Runnable {

	protected int result = Pcap.OK;

	protected Thread thread;

	protected final Pcap pcap;

	protected final int count;

	protected final PcapHandler handler;

	protected final Object user;

	protected boolean isSynched = false;

	/**
	 * @param pcap
	 */
	public PcapTask(Pcap pcap, int count, PcapHandler handler, Object user) {
		this.pcap = pcap;
		this.count = count;
		this.handler = handler;
		this.user = user;
	}

	public final int getResult() {
		return this.result;
	}

	public final Thread getThread() {
		return this.thread;
	}

	public void start() throws InterruptedException {
		if (thread != null) {
			stop();
		}

		/*
		 * Use our own Runnable in order to synchronize the start of the thread. We
		 * delegate to the user overriden run() method after the setup synching is
		 * done.
		 */
		thread = new Thread(new Runnable() {

			public void run() {
				Thread.yield(); // needed for the synch, parent T enters wait state
				synchronized (PcapTask.this) {
					PcapTask.this.notifyAll();
					PcapTask.this.isSynched = true;
				}

				/*
				 * Delegate to user overriden Runnable
				 */
				PcapTask.this.run();
			}

		}, (user != null) ? user.toString() : pcap.toString());

		/*
		 * Now we are sure that thread has started and entered its loop
		 */
		synchronized (PcapTask.this) {
			thread.start();
			PcapTask.this.wait();
			Thread.yield(); // allow Runnable to enter delegate run
		}
	}

	/**
	 * <p>
	 * Terminates the task using a Pcap.breakLoop() call after making sure that
	 * the pcap session and thread are active.
	 * </p>
	 * <p>
	 * Notes on breakLoop() and its behaviour which directly applies to behaviour
	 * of this method.
	 * 
	 * @throws InterruptedException
	 */
	public void stop() throws InterruptedException {
		if (thread == null || thread.isAlive() == false) {
			/*
			 * Nothing to do
			 */
			return;
		}

		synchronized (this) {
			if (isSynched == false) {
				throw new IllegalStateException(
				    "Unable to synchronize task with parent thread");
			}
		}

		/*
		 * Tell pcap we want to break out of the loop
		 */
		thread.interrupt();
		thread.join(); // Wait for thread to finish and exit

		// pcap.breakloop();
		// thread.join();
	}

	public boolean isAlive() {
		return thread != null && thread.isAlive();
	}

	public final Pcap getPcap() {
		return this.pcap;
	}

	public final int getCount() {
		return this.count;
	}

	public final PcapHandler getHandler() {
		return this.handler;
	}

	public final Object getUser() {
		return this.user;
	}

}