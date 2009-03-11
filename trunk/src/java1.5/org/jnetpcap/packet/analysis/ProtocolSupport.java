/**
 * Copyright (C) 2009 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jnetpcap.packet.analysis;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public abstract class ProtocolSupport<L, D> {

	private List<L> listeners = new ArrayList<L>();

	public boolean add(L o) {
	  return this.listeners.add(o);
  }

	public boolean isEmpty() {
	  return this.listeners.isEmpty();
  }

	public Iterator<L> iterator() {
	  return this.listeners.iterator();
  }

	public boolean remove(Object o) {
	  return this.listeners.remove(o);
  }

	public int size() {
	  return this.listeners.size();
  }
	
	public void fire(D data) {
		for (L l: listeners) {
			dispatch(l, data);
		}
	}
	
	protected abstract void dispatch(L listener, D data);
}
