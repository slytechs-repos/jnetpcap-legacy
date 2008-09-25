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

	private static final long DEFAULT_BREAK_LOOP_DELAY = 100; // 100 ms delay

	protected int result = Pcap.OK;

	protected Thread thread;

	protected final Pcap pcap;

	protected final int count;

	protected final PcapHandler handler;

	protected final Object user;

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

	public void start() {
		if (thread != null) {
			stop();
		}

		thread =
		    new Thread(this, (user != null) ? user.toString() : pcap.toString());

		thread.start();
	}

	/**
	 * <p>
	 * Terminates the task using a Pcap.breakLoop() call after making sure that
	 * the pcap session and thread are active.
	 * </p>
	 * <p>
	 * Notes on breakLoop() and its behaviour which directly applies to behaviour
	 * of this method.
	 */
	public void stop() {
		if (thread == null || thread.isAlive() == false) {
			/*
			 * Nothing to do
			 */
			return;
		}
		/*
		 * Put the thread to sleep, to prevent multi-threaded timing issues in case
		 * the loop has been called but not yet entered. Otherwise a coredump will
		 * result.
		 */
		try {
			Thread.sleep(DEFAULT_BREAK_LOOP_DELAY);
		} catch (InterruptedException e) {
			// Empty, no need to report interruptions
		}

		/*
		 * Tell pcap we want to break out of the loop
		 */
		pcap.breakloop();
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