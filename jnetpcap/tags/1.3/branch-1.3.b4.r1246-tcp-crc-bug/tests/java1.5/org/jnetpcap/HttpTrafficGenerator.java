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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.atomic.AtomicBoolean;

// TODO: Auto-generated Javadoc
/**
 * The Class HttpTrafficGenerator.
 */
public class HttpTrafficGenerator implements Runnable {

	/** The Constant SLEEP. */
	private static final long SLEEP = 100; // 100 millis

	/** The timeout. */
	private long timeout = 5 * 1000; // Timeout in 5 seconds

	/** The runflag. */
	private final AtomicBoolean runflag = new AtomicBoolean(false);

	/** The worker. */
	private final Thread worker;

	/** The website. */
	private URL website;

	/**
	 * Instantiates a new http traffic generator.
	 * 
	 * @param timeout
	 *          the timeout
	 * @param website
	 *          the website
	 */
	public HttpTrafficGenerator(long timeout, URL website) {
		this.timeout = timeout;
		this.website = website;

		worker = new Thread(this, "HttpTrafficGenerator");
	}

	/**
	 * Instantiates a new http traffic generator.
	 * 
	 * @param timeout
	 *          the timeout
	 */
	public HttpTrafficGenerator(long timeout) {
		this.timeout = timeout;

		worker = new Thread(this, "HttpTrafficGenerator");
		try {
			website = new URL("http://google.com");
		} catch (MalformedURLException e) {
			throw new IllegalStateException("Internal error", e);
		}
	}

	/**
	 * Instantiates a new http traffic generator.
	 */
	public HttpTrafficGenerator() {

		worker = new Thread(this, "HttpTrafficGenerator");
		try {
			website = new URL("http://google.com");
		} catch (MalformedURLException e) {
			throw new IllegalStateException("Internal error", e);
		}
	}

	/**
	 * Start.
	 */
	public void start() {

		if (worker.isAlive()) {
			throw new IllegalStateException(
			    "Worker thread is still alive, unexpected.");
		}

		if (runflag.get()) {
			throw new IllegalStateException(
			    "Runflag is inconsistant with thread, unexpected.");
		}

		runflag.set(true);
		worker.start();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Runnable#run()
	 */
	public void run() {

		long ts = System.currentTimeMillis();

		int count = 0;
		while (runflag.get()) {
			try {
				@SuppressWarnings("unused")
				Object o = website.getContent(); // Get the webpage

				// System.out.printf("Worker working. content=%s\n", o.toString());

				Thread.sleep(SLEEP); // 100 millis

			} catch (Exception e) {
				e.printStackTrace();
				break;
			}

			if (System.currentTimeMillis() - ts > timeout) {
				break; // Break out on our own
			}
			count++;
		}

		/*
		 * Just incase we use break to breakout of the loop, we need to make sure
		 * runflag is consistant with the worker thread state.
		 */
		runflag.set(false);
	}

	/**
	 * Stop.
	 */
	public void stop() {
		runflag.set(false);

		while (worker.isAlive()) {
			try {
				Thread.sleep(10); // Wait until it stops
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
}
