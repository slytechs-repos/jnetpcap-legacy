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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

// TODO: Auto-generated Javadoc
/**
 * The Class PcapPacketArrayList.
 */
public class PcapPacketArrayList
    implements
    List<PcapPacket>,
    RandomAccess,
    Serializable,
    PcapPacketHandler<Object> {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -6379668946303974430L;

	/** The list. */
	private final ArrayList<PcapPacket> list;

	/**
	 * Instantiates a new pcap packet array list.
	 */
	public PcapPacketArrayList() {
		list = new ArrayList<PcapPacket>();
	}

	/**
	 * Instantiates a new pcap packet array list.
	 * 
	 * @param initialCapacity
	 *          the initial capacity
	 */
	public PcapPacketArrayList(int initialCapacity) {
		list = new ArrayList<PcapPacket>(initialCapacity);
	}

	/**
	 * Instantiates a new pcap packet array list.
	 * 
	 * @param collection
	 *          the collection
	 */
	public PcapPacketArrayList(Collection<? extends PcapPacket> collection) {
		list = new ArrayList<PcapPacket>(collection);
	}

	/* (non-Javadoc)
	 * @see java.util.List#add(int, java.lang.Object)
	 */
	public void add(int index, PcapPacket element) {
		this.list.add(index, element);
	}

	/* (non-Javadoc)
	 * @see java.util.List#add(java.lang.Object)
	 */
	public boolean add(PcapPacket o) {
		return this.list.add(o);
	}

	/* (non-Javadoc)
	 * @see java.util.List#addAll(java.util.Collection)
	 */
	public boolean addAll(Collection<? extends PcapPacket> c) {
		return this.list.addAll(c);
	}

	/* (non-Javadoc)
	 * @see java.util.List#addAll(int, java.util.Collection)
	 */
	public boolean addAll(int index, Collection<? extends PcapPacket> c) {
		return this.list.addAll(index, c);
	}

	/* (non-Javadoc)
	 * @see java.util.List#clear()
	 */
	public void clear() {
		this.list.clear();
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#clone()
	 */
	public Object clone() {
		return this.list.clone();
	}

	/* (non-Javadoc)
	 * @see java.util.List#contains(java.lang.Object)
	 */
	public boolean contains(Object elem) {
		return this.list.contains(elem);
	}

	/* (non-Javadoc)
	 * @see java.util.List#containsAll(java.util.Collection)
	 */
	public boolean containsAll(Collection<?> c) {
		return this.list.containsAll(c);
	}

	/**
	 * Ensure capacity.
	 * 
	 * @param minCapacity
	 *          the min capacity
	 */
	public void ensureCapacity(int minCapacity) {
		this.list.ensureCapacity(minCapacity);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object o) {
		return this.list.equals(o);
	}

	/* (non-Javadoc)
	 * @see java.util.List#get(int)
	 */
	public PcapPacket get(int index) {
		return this.list.get(index);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return this.list.hashCode();
	}

	/* (non-Javadoc)
	 * @see java.util.List#indexOf(java.lang.Object)
	 */
	public int indexOf(Object elem) {
		return this.list.indexOf(elem);
	}

	/* (non-Javadoc)
	 * @see java.util.List#isEmpty()
	 */
	public boolean isEmpty() {
		return this.list.isEmpty();
	}

	/* (non-Javadoc)
	 * @see java.util.List#iterator()
	 */
	public Iterator<PcapPacket> iterator() {
		return this.list.iterator();
	}

	/* (non-Javadoc)
	 * @see java.util.List#lastIndexOf(java.lang.Object)
	 */
	public int lastIndexOf(Object elem) {
		return this.list.lastIndexOf(elem);
	}

	/* (non-Javadoc)
	 * @see java.util.List#listIterator()
	 */
	public ListIterator<PcapPacket> listIterator() {
		return this.list.listIterator();
	}

	/* (non-Javadoc)
	 * @see java.util.List#listIterator(int)
	 */
	public ListIterator<PcapPacket> listIterator(int index) {
		return this.list.listIterator(index);
	}

	/* (non-Javadoc)
	 * @see java.util.List#remove(int)
	 */
	public PcapPacket remove(int index) {
		return this.list.remove(index);
	}

	/* (non-Javadoc)
	 * @see java.util.List#remove(java.lang.Object)
	 */
	public boolean remove(Object o) {
		return this.list.remove(o);
	}

	/* (non-Javadoc)
	 * @see java.util.List#removeAll(java.util.Collection)
	 */
	public boolean removeAll(Collection<?> c) {
		return this.list.removeAll(c);
	}

	/* (non-Javadoc)
	 * @see java.util.List#retainAll(java.util.Collection)
	 */
	public boolean retainAll(Collection<?> c) {
		return this.list.retainAll(c);
	}

	/* (non-Javadoc)
	 * @see java.util.List#set(int, java.lang.Object)
	 */
	public PcapPacket set(int index, PcapPacket element) {
		return this.list.set(index, element);
	}

	/* (non-Javadoc)
	 * @see java.util.List#size()
	 */
	public int size() {
		return this.list.size();
	}

	/* (non-Javadoc)
	 * @see java.util.List#subList(int, int)
	 */
	public List<PcapPacket> subList(int fromIndex, int toIndex) {
		return this.list.subList(fromIndex, toIndex);
	}

	/* (non-Javadoc)
	 * @see java.util.List#toArray()
	 */
	public Object[] toArray() {
		return this.list.toArray();
	}

	/* (non-Javadoc)
	 * @see java.util.List#toArray(T[])
	 */
	public <T> T[] toArray(T[] a) {
		return this.list.toArray(a);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return this.list.toString();
	}

	/**
	 * Trim to size.
	 */
	public void trimToSize() {
		this.list.trimToSize();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.PcapPacketHandler#nextPacket(org.jnetpcap.packet.PcapPacket,
	 *      java.lang.Object)
	 */
	public void nextPacket(PcapPacket packet, Object user) {
		list.add(packet);
	}
}
