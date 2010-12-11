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
package org.jnetpcap;

// TODO: Auto-generated Javadoc
/**
 * The Class PcapTask.
 * 
 * @param <T>
 *          the generic type
 */
public abstract class PcapTask<T> implements Runnable {

	/** The result. */
	protected int result = Pcap.OK;

	/** The thread. */
	protected Thread thread;

	/** The pcap. */
	protected final Pcap pcap;

	/** The count. */
	protected final int count;

	/** The user. */
	protected final T user;

	/**
	 * Instantiates a new pcap task.
	 * 
	 * @param pcap
	 *          the pcap
	 * @param count
	 *          the count
	 * @param user
	 *          the user
	 */
	public PcapTask(Pcap pcap, int count, T user) {
		this.pcap = pcap;
		this.count = count;
		this.user = user;
	}

	/**
	 * Gets the libpcap result code.
	 * 
	 * @return the libpcap result code
	 */
	public final int getResult() {
		return this.result;
	}

	/**
	 * Gets the controlling thread.
	 * 
	 * @return the controlling thread
	 */
	public final Thread getThread() {
		return this.thread;
	}

	/**
	 * Start.
	 * 
	 * @throws InterruptedException
	 *           the interrupted exception
	 */
	public void start() throws InterruptedException {
		if (thread != null) {
			stop();
		}

		/*
		 * Use our own Runnable in order to synchronize the start of the thread. We
		 * delegate to the user overriden run() method after the setup synching is
		 * done.
		 */
		thread =
	    new Thread(new Runnable() {

				public void run() {
					PcapTask.this.run();
					thread = null; // Cleanup
        }
	    	
	    }, (user != null) ? user.toString() : pcap.toString());

		thread.setDaemon(true);
		thread.start();
	}

	/**
	 * Stop.
	 * 
	 * @throws InterruptedException
	 *           the interrupted exception
	 */
	public void stop() throws InterruptedException {
		if (thread == null || thread.isAlive() == false) {
			/*
			 * Nothing to do
			 */
			return;
		}

		/*
		 * Tell pcap we want to break out of the loop
		 */
		breakLoop();
		thread.join(); // Wait for thread to finish and exit
	}
	
	/**
	 * Break loop.
	 */
	protected void breakLoop() {
		pcap.breakloop();
	}

	/**
	 * Checks if is alive.
	 * 
	 * @return true, if is alive
	 */
	public boolean isAlive() {
		return thread != null && thread.isAlive();
	}

	/**
	 * Gets the pcap handle.
	 * 
	 * @return the pcap handle
	 */
	public final Pcap getPcap() {
		return this.pcap;
	}

	/**
	 * Gets the number of packets to capture or 0 for infinate.
	 * 
	 * @return the number of packets to capture or 0 for infinate
	 */
	public final int getCount() {
		return this.count;
	}

	/**
	 * Gets the user data.
	 * 
	 * @return the user data
	 */
	public final T getUser() {
		return this.user;
	}

}