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

import java.io.IOException;

// TODO: Auto-generated Javadoc
/**
 * The Class Measurement.
 */
public abstract class Measurement {

	/** The counter. */
	protected long counter;
	
	/** The total. */
	protected long total;

	/**
	 * Instantiates a new measurement.
	 */
	public Measurement() {
		reset();
	}

	/**
	 * Snapshot baseline.
	 */
	public void snapshotBaseline() {
		// Empty
	}

	/**
	 * Reset.
	 */
	public abstract void reset();

	/**
	 * Snapshot.
	 */
  public void snapshot() {
    
  	this.total += this.counter;  
  	this.counter = 0;
  }

	/**
	 * Report.
	 * 
	 * @param out
	 *          the out
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public abstract void report(Appendable out) throws IOException;

	/**
	 * Report.
	 * 
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public void report() throws IOException {
		report(System.out);
	}

	/**
	 * Result.
	 * 
	 * @return the string
	 */
	public String result() {
		final StringBuilder b = new StringBuilder(10 * 1024);

		try {
			report(b);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}

		return b.toString();
	}

}
