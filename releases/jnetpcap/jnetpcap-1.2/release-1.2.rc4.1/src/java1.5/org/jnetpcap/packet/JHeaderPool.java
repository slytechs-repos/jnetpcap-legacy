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
 * A thread local pool of instances of headers. The header pool keeps track of
 * instances of headers it allocates based on protocol and thread IDs. The class
 * allows private pools and also provides a global singleton pool which can be
 * referenced from anywhere.
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
	 * Gets an instance of a header for the given ID type. The headers are
	 * allocated on a per thread basis. Eath thread uses its own pool of instance
	 * headers. A call with the same ID and within the same thread will return the
	 * same exact instance of a header that was returned from a previous call
	 * using the same ID and thread.
	 * 
	 * @param id
	 *          numerical ID of the protocol header as assigned by JRegistry
	 * @return a shared instance of a header per thread per ID
	 * @throws UnregisteredHeaderException
	 *           thrown if ID is invalid
	 */
	public JHeader getHeader(int id) throws UnregisteredHeaderException {
		return getHeader(JRegistry.lookupClass(id), id);
	}

	/**
	 * Gets an instance of a header for the protocol constant. The headers are
	 * allocated on a per thread basis. Eath thread uses its own pool of instance
	 * headers. A call with the same ID and within the same thread will return the
	 * same exact instance of a header that was returned from a previous call
	 * using the same ID and thread.
	 * <p>
	 * This method does not throw an exception since all core protocols are always
	 * registered and always accessible.
	 * </p>
	 * 
	 * @param protocol
	 *          core protocol constant
	 * @return a shared instance of a header per thread per ID
	 */
	public <T extends JHeader> T getHeader(JProtocol protocol) {
		return (T) getHeader(protocol.getHeaderClass(), protocol.getId());
	}

	/**
	 * Gets an instance of a header for the given ID type. The headers are
	 * allocated on a per thread basis. Eath thread uses its own pool of instance
	 * headers. A call with the same ID and within the same thread will return the
	 * same exact instance of a header that was returned from a previous call
	 * using the same ID and thread.
	 * 
	 * @param <T>
	 *          header class name
	 * @param clazz
	 *          parameterized class name that the retrieved header instance will
	 *          be cast to
	 * @param id
	 *          numerical ID of the protocol header as assigned by JRegistry
	 * @return a shared instance of a header per thread per ID
	 * @throws UnregisteredHeaderException
	 *           thrown if ID is invalid
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
	 * Gets a default global instance of this header pool.
	 */
	public static JHeaderPool getDefault() {
		return local;
	}

}
