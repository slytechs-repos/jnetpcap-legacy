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

/**
 * A utility class that facilitates taking measurements and reports.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class LongCounter {

	private long counter;

	private long total;
	
	final private String units;
	
	final private String u;
	
	public LongCounter(String units, String u) {
		this.units = units;
		this.u = u;
		
		reset();
	}

	/**
	 * Setup measurement using its defaults
	 */
	public LongCounter(String units) {
		this(units, "" + units.charAt(0));
	}
	
	public LongCounter() {
		this("bytes");
	}

	/**
	 * Measurement takes a snapshot which it then uses as a baseline (zeroed out
	 * starting point) for whatever measurement it is taking. So for example
	 */
	public void snapshotBaseline() {
		// Empty
	}

	/**
	 * Initializes the test to its defaults
	 */
	public void reset() {
		this.counter = 0;
		this.total = 0;
	}

	/**
	 * Takes a measurment snapshot and updates its counters. This is where
	 * measurement calculations stem from such as packet rates or bit rates.
	 */
	public void snapshot() {
		this.counter = 0;
	}

	public void inc(long delta) {
		counter += delta;
		total += delta;
	}
	
	public void set(long value) {
		counter = value;
		total = value;
	}

	public long counter() {
		return this.counter;
	}

	public long total() {
		return this.total;
	}
	
	public String units() {
		return this.units;
	}
	
	public String u() {
		return this.u;
	}

}
