/**
 * Copyright (C) 2010 Sly Technologies, Inc.
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
package org.jnetpcap.packet;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class PcapRecordList implements List<PcapRecord> {
	
	private final List<PcapRecord> list = new ArrayList<PcapRecord>();

	public void add(int index, PcapRecord element) {
	  this.list.add(index, element);
  }

	public boolean add(PcapRecord o) {
	  return this.list.add(o);
  }

	public boolean addAll(Collection<? extends PcapRecord> c) {
	  return this.list.addAll(c);
  }

	public boolean addAll(int index, Collection<? extends PcapRecord> c) {
	  return this.list.addAll(index, c);
  }

	public void clear() {
	  this.list.clear();
  }

	public boolean contains(Object o) {
	  return this.list.contains(o);
  }

	public boolean containsAll(Collection<?> c) {
	  return this.list.containsAll(c);
  }

	public boolean equals(Object o) {
	  return this.list.equals(o);
  }

	public PcapRecord get(int index) {
	  return this.list.get(index);
  }

	public int hashCode() {
	  return this.list.hashCode();
  }

	public int indexOf(Object o) {
	  return this.list.indexOf(o);
  }

	public boolean isEmpty() {
	  return this.list.isEmpty();
  }

	public Iterator<PcapRecord> iterator() {
	  return this.list.iterator();
  }

	public int lastIndexOf(Object o) {
	  return this.list.lastIndexOf(o);
  }

	public ListIterator<PcapRecord> listIterator() {
	  return this.list.listIterator();
  }

	public ListIterator<PcapRecord> listIterator(int index) {
	  return this.list.listIterator(index);
  }

	public PcapRecord remove(int index) {
	  return this.list.remove(index);
  }

	public boolean remove(Object o) {
	  return this.list.remove(o);
  }

	public boolean removeAll(Collection<?> c) {
	  return this.list.removeAll(c);
  }

	public boolean retainAll(Collection<?> c) {
	  return this.list.retainAll(c);
  }

	public PcapRecord set(int index, PcapRecord element) {
	  return this.list.set(index, element);
  }

	public int size() {
	  return this.list.size();
  }

	public List<PcapRecord> subList(int fromIndex, int toIndex) {
	  return this.list.subList(fromIndex, toIndex);
  }

	public Object[] toArray() {
	  return this.list.toArray();
  }

	public <T> T[] toArray(T[] a) {
	  return this.list.toArray(a);
  }

}
