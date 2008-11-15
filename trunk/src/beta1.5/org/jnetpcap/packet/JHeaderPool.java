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
package org.jnetpcap.packet;

/**
 * A thread local pool of instances of headers.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@SuppressWarnings("unchecked")
public class JHeaderPool {

	private static JHeaderPool local = new JHeaderPool();

	private ThreadLocal<? extends JHeader>[] locals =
	    new ThreadLocal[JRegistry.MAX_ID_COUNT];
	
	/**
	 * @param id
	 * @return
	 * @throws UnregisteredHeaderException
	 */
	public JHeader getHeader(int id)
	    throws UnregisteredHeaderException {
		return getHeader(JRegistry.lookupClass(id), id);
	}
	
	public <T extends JHeader> T getHeader(JProtocol protocol)  {
		return (T) getHeader(protocol.clazz, protocol.ID);
	}

	/**
	 * @param id
	 * @return
	 */
	public <T extends JHeader> T getHeader(final Class<T> clazz, int id) {

		ThreadLocal<T> local = (ThreadLocal<T>) locals[id];
		if (local == null) {
			local = new ThreadLocal<T>() {

				@Override
				protected T initialValue() {
					try {
						return  clazz.newInstance();
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
	 * 
	 */
	public static JHeaderPool getDefault() {
		return local;
	}

}
