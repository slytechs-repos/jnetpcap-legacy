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
package org.jnetpcap;

/**
 * A utility class that facilitates taking measurements and reports.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class ResourceMeasurement {

	/**
	 * Setup measurement using its defaults
	 */
	public ResourceMeasurement() {
		reset();
	}

	/**
	 * Initializes the test to its defaults
	 */
	public abstract void reset();

	/**
	 * Takes a measurment snapshot and updates its counters. This is where
	 * measurement calculations stem from such as packet rates or bit rates.
	 */
	public abstract void snapshot();

	/**
	 * Generates a report and sends out to output.
	 * 
	 * @param out
	 *          destination where to send the report
	 */
	public abstract void report(Appendable out);

	/**
	 * Generates a report and sends it out to standard output
	 */
	public void report() {
		report(System.out);
	}

	/**
	 * Generates a report and returns it as a string.
	 * 
	 * @return terse report generated from the measurements
	 */
	public String result() {
		StringBuilder b = new StringBuilder(10 * 1024);

		report(b);

		return b.toString();
	}

}
