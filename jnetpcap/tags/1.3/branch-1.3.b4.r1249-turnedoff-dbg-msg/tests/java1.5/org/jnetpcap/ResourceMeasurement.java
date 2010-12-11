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
 * The Class ResourceMeasurement.
 */
public abstract class ResourceMeasurement {

	/**
	 * Instantiates a new resource measurement.
	 */
	public ResourceMeasurement() {
		reset();
	}

	/**
	 * Reset.
	 */
	public abstract void reset();

	/**
	 * Snapshot.
	 */
	public abstract void snapshot();

	/**
	 * Report.
	 * 
	 * @param out
	 *          the out
	 */
	public abstract void report(Appendable out);

	/**
	 * Report.
	 */
	public void report() {
		report(System.out);
	}

	/**
	 * Result.
	 * 
	 * @return the string
	 */
	public String result() {
		StringBuilder b = new StringBuilder(10 * 1024);

		report(b);

		return b.toString();
	}

}
