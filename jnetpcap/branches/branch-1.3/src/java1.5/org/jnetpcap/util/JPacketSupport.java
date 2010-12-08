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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;

/**
 * A utility class that dispatches a JPacket to any number of listeners. The
 * packet is simply forwarded to any listeners as is.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JPacketSupport implements JPacketHandler<Object> {

	private static class Entry {
		public JPacketHandler<Object> handler;

		public Object user;

		/**
		 * @param handler
		 * @param user
		 */
		@SuppressWarnings("unchecked")
		public Entry(JPacketHandler<?> handler, Object user) {
			this.handler = (JPacketHandler<Object>) handler;
			this.user = user;
		}

	}

	private List<Entry> listeners = new ArrayList<Entry>();

	private Entry[] listenersArray = null;

	public <T> boolean add(JPacketHandler<T> o, T user) {
		listenersArray = null; // reset

		return this.listeners.add(new Entry(o, user));
	}

	public boolean remove(JPacketHandler<?> o) {
		listenersArray = null;

		for (Iterator<Entry> i = listeners.iterator(); i.hasNext();) {
			Entry e = i.next();
			if (o == e.handler) {
				i.remove();

				listenersArray = null; // reset
				return true;
			}
		}

		return false;
	}

	public void fireNextPacket(JPacket packet) {
		if (listenersArray == null) {
			listenersArray = listeners.toArray(new Entry[listeners.size()]);
		}

		/*
		 * More efficient to loop through array than iterator
		 */
		for (Entry e : listenersArray) {
			e.handler.nextPacket(packet, e.user);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.JPacketHandler#nextPacket(org.jnetpcap.packet.JPacket,
	 *      java.lang.Object)
	 */
	public void nextPacket(JPacket packet, Object user) {
		fireNextPacket(packet);
	}

}
