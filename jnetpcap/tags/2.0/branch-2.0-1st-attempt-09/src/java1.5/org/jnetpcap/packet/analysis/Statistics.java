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
package org.jnetpcap.packet.analysis;

/**
 * A collection of statistics. The interface provides methods for accessing
 * ongoing statistic collection. At any time a snapshot of current statistics
 * can be taken using the method <code>snapshot</code>. The method will
 * return a table of current statistics. The returned table is a copy of the
 * original statistics data and modifying it will not have any effect on the
 * source data. Also, you can request to retrieve a table of string labels that
 * correspond to each entry within the snapshot table. The index within the
 * snapshot table and the label table contain related values.
 * <p>
 * The total is the cummulitive total for all the statistics that were collected
 * if that makes sense.
 * </p>
 * <p>
 * You can also request that the statistics table be reset to its initial state
 * with the <code>reset</code> method.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface Statistics {

	/**
	 * Labels to go along with each entry in the snapshot table.
	 * 
	 * @return array of labels that correspond to snapshot table
	 */
	public abstract String[] labels();

	/**
	 * Requests that the state of the collector be reset to its initial state
	 */
	public abstract void reset();

	/**
	 * Takes a snapshot of the currently collected data by making a copy of it and
	 * returning it.
	 * 
	 * @return a snapshot in time of the collected data so far
	 */
	public abstract long[] snapshot();

	/**
	 * Gets the total number of opaque elements collected so far.
	 * 
	 * @return a grand total of something
	 */
	public abstract long total();

	/**
	 * Report the size of the snapshot table and size of the labels table returned
	 * by this collector.
	 * 
	 * @return number of elements found in the snapshot and labels arrays
	 */
	public abstract int size();

}