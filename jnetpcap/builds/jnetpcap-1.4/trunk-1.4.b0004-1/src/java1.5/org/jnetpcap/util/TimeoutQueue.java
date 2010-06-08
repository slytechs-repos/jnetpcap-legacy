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

import java.util.Iterator;
import java.util.PriorityQueue;
import java.util.Queue;


/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TimeoutQueue {

	/**
	 * This queue contains various analysis objects that are time constrained.
	 * Such as IP fragmentation. If all the fragments don't arrive within a
	 * reassembly time window, then we timeout that analysis object, remove it
	 * from maps and notify any listeners that analysis expired. The time is taken
	 * from all arriving packets as they are read. Their timestamp determines the
	 * current processing time (which is different from current system clock as we
	 * might be reading from a file using saved timestamps.
	 */
	private Queue<Timeout> timeoutQueue = new PriorityQueue<Timeout>();

	/**
	 * 
	 */
	public void timeout(long timeInMillis) {
		if (timeoutQueue.isEmpty()
		    || timeoutQueue.peek().isTimedout(timeInMillis) == false) {
			return;
		}

		for (Iterator<Timeout> i = timeoutQueue.iterator(); i.hasNext();) {
			Timeout entry = i.next();
			if (entry.isTimedout(timeInMillis)) {
				i.remove();
				entry.timeout();

			} else {
				break;
			}
		}
	}

	public boolean timeout(Timeout entry) {
		entry.timeout();

		return remove(entry);
	}

	public boolean isEmpty() {
		return timeoutQueue.isEmpty();
	}

	public boolean add(Timeout o) {
		return this.timeoutQueue.add(o);
	}

	public boolean remove(Timeout o) {
		return this.timeoutQueue.remove(o);
	}

}
