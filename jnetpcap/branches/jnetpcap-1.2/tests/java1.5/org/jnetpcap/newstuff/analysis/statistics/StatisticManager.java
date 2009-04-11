/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.newstuff.analysis.statistics;

import java.util.Arrays;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unused")
public class StatisticManager {

	public enum Catetory implements Ordinal {
		ANALYZER_GENERAL("general statistics about all analyzers"),
		HEADER_COUNT_TABLE("statistic about protocol counts"),
		HEADER_LENGTH_TABLE("statistics about each header's length"),
		STATISTIC_MANAGER_GENERAL(
		    "general statistics abount statistic manager usage")

		;

		private final String description;

		public final int ID;

		private Catetory(String description) {
			this.description = description;

			this.ID = getDefault().getCategory(this.name(), description);
		}

		public final String getDescription() {
			return this.description;
		}
	}

	public interface Counters {

		public void clear(int id);

		public void close();

		public int count();

		public void dec(int id);

		public long deltaInMillis();

		public long endInMillis();

		public long get(int id);

		public double getRate(int id);

		public void inc(int id);
		
		public void inc(int id, int delta);
		
		public boolean isActive();

		public long startInMillis();

		public long[] toArray();

		public long[] toArray(long[] storage);
	}

	private static class JavaCounters implements Counters {
		private boolean active;

		private final long[] counters;

		private long end;

		private final long start;

		public JavaCounters(int count) {
			this.counters = new long[count];
			this.active = true;
			this.start = System.currentTimeMillis();
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#clear(int)
		 */
		public void clear(int id) {
			this.counters[id] = 0;
		}

		/* (non-Javadoc)
     * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#close()
     */
    public void close() {
	    this.active = false;
	    this.end = System.currentTimeMillis();
    }

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#count()
		 */
		public int count() {
			return this.counters.length;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#dec(int)
		 */
		public void dec(int id) {
			this.counters[id]--;
		}

		/* (non-Javadoc)
     * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.IntervalCounters#deltaInMillis()
     */
    public long deltaInMillis() {
    	if (this.end == 0) {
    		return System.currentTimeMillis() - this.start;
    	} else {
    		return this.end - this.start;
    	}
    }

		/* (non-Javadoc)
     * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.IntervalCounters#endInMillis()
     */
    public long endInMillis() {
	    return this.end;
    }

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#get(int)
		 */
		public long get(int id) {
			return this.counters[id];
		}

		/* (non-Javadoc)
     * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.IntervalCounters#getRate(int)
     */
    public double getRate(int id) {
	    double d = get(id) / deltaInMillis() / 1000;
	    
	    return d;
    }

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#inc(int)
		 */
		public void inc(int id) {
			this.counters[id]++;
		}
    
		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#inc(int,
		 *      int)
		 */
		public void inc(int id, int delta) {
			this.counters[id] += delta;
		}
		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#isActive()
		 */
		public boolean isActive() {
			return this.active;
		}


		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#reset()
		 */
		public void reset() {
			Arrays.fill(this.counters, 0);
		}

		/* (non-Javadoc)
     * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.IntervalCounters#startInMillis()
     */
    public long startInMillis() {
	    return this.start;
    }

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#toArray()
		 */
		public long[] toArray() {
			final long[] a;
			System.arraycopy(this.counters, 0, a = new long[count()], 0, count());

			return a;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.analysis.statistics.StatisticManager.Counters#toArray(long[])
		 */
		public long[] toArray(long[] storage) {
			if (count() != storage.length) {
				throw new IllegalArgumentException("array lengths must match");
			}

			System.arraycopy(this.counters, 0, storage, 0, count());

			return storage;
		}
	}

	private static class IntervalCounters  {

		/**
     * @param count
     */
    public IntervalCounters(int count) {
    }

	}

	public interface CounterCollector {
		public Counters getCounters();
		
		public Counters freezeCounters();
	}
	
	
	public interface Ordinal {
		public int ordinal();
	}

	private static StatisticManager global = new StatisticManager();

	public static StatisticManager getDefault() {
		return global;
	}

	private int lastCategory = 0;

	public int getCategory(String name, String description) {
		return lastCategory++;
	}

	public Counters getCounters(int category) {
		return null;
	}

}
