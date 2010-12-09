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
package org.jnetpcap.packet;

import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Class JHeaderPool.
 */
@SuppressWarnings("unchecked")
public class JHeaderPool {

	/** The local. */
	private static JHeaderPool local = new JHeaderPool();

	/** The locals. */
	private ThreadLocal<? extends JHeader>[] locals =
	    new ThreadLocal[JRegistry.MAX_ID_COUNT];

	/**
	 * Gets the header.
	 * 
	 * @param id
	 *          the id
	 * @return the header
	 * @throws UnregisteredHeaderException
	 *           the unregistered header exception
	 */
	public JHeader getHeader(int id) throws UnregisteredHeaderException {
		return getHeader(JRegistry.lookupClass(id), id);
	}

	/**
	 * Gets the header.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param protocol
	 *          the protocol
	 * @return the header
	 */
	public <T extends JHeader> T getHeader(JProtocol protocol) {
		return (T) getHeader(protocol.getHeaderClass(), protocol.getId());
	}

	/**
	 * Gets the header.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param clazz
	 *          the clazz
	 * @param id
	 *          the id
	 * @return the header
	 */
	public <T extends JHeader> T getHeader(final Class<T> clazz, int id) {

		ThreadLocal<T> local = (ThreadLocal<T>) locals[id];
		if (local == null) {
			local = new ThreadLocal<T>() {

				@Override
				protected T initialValue() {
					try {
						return clazz.newInstance();
					} catch (Exception e) {
						throw new IllegalStateException(e);
					}
				}
			};

			locals[id] = local;
		}

		return local.get();
	}

	/**
	 * Gets the default.
	 * 
	 * @return the default
	 */
	public static JHeaderPool getDefault() {
		return local;
	}

}
