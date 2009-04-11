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
package org.jnetpcap.analysis;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public class AnalyzerSupport<E extends AnalyzerEvent> {

	private static class Entry<E extends AnalyzerEvent> implements
	    Comparable<AnalyzerListener<E>> {
		/**
		 * @param listener
		 * @param user
		 */
		public Entry(AnalyzerListener<E> listener, Object user) {
			this.listener = listener;
			this.user = user;
		}

		public AnalyzerListener<E> listener;

		public Object user;

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Comparable#compareTo(java.lang.Object)
		 */
		public int compareTo(AnalyzerListener<E> o) {
			return (this.listener == o) ? 0 : 1;
		}
	}

	protected List<Entry<E>> listeners = new ArrayList<Entry<E>>();

	public <U> boolean addListener(AnalyzerListener<E> listener, U user) {
		listeners.add(new Entry<E>(listener, user));
		return true;
	}

	public boolean removeListener(AnalyzerListener<E> listener) {
		int index = Collections.binarySearch(listeners, listener);
		listeners.remove(index);

		return true;
	}

	public void fire(E evt) {

		for (Entry<E> e : listeners) {
			e.listener.processAnalyzerEvent(evt);
		}
	}
}