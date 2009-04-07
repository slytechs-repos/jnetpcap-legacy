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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * A utility class that dispatches a PcapPacket to any number of listeners. The
 * packet is simply forwarded to any listeners as is.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapPacketSupport implements PcapPacketHandler<Object>{

	private static class Entry {
		public PcapPacketHandler<Object> handler;

		public Object user;

		/**
		 * @param handler
		 * @param user
		 */
		@SuppressWarnings("unchecked")
		public Entry(PcapPacketHandler<?> handler, Object user) {
			this.handler = (PcapPacketHandler<Object>) handler;
			this.user = user;
		}

	}

	private List<Entry> listeners = new ArrayList<Entry>();

	private Entry[] listenersArray = null;

	public <T> boolean add(PcapPacketHandler<T> o, T user) {
		listenersArray = null; // reset

		return this.listeners.add(new Entry(o, user));
	}

	public boolean remove(PcapPacketHandler<?> o) {
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

	public void fireNextPacket(PcapPacket packet) {
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

	/* (non-Javadoc)
   * @see org.jnetpcap.packet.PcapPacketHandler#nextPacket(org.jnetpcap.packet.PcapPacket, java.lang.Object)
   */
  public void nextPacket(PcapPacket packet, Object user) {
  	fireNextPacket(packet);
  }

}
