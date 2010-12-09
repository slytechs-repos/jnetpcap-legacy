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
package org.jnetpcap.util.resolver;

import java.io.IOException;
import java.net.URL;

// TODO: Auto-generated Javadoc
/**
 * The Interface Resolver.
 */
public interface Resolver {
	
	/**
	 * The Enum ResolverType.
	 */
	public enum ResolverType {
		
		/** The IEE e_ ou i_ address. */
		IEEE_OUI_ADDRESS,

		/** The IEE e_ ou i_ prefix. */
		IEEE_OUI_PREFIX(new IEEEOuiPrefixResolver()),

		/** The IP. */
		IP(new IpResolver()),

		/** The PORT. */
		PORT, ;

		/** The resolver. */
		private final Resolver resolver;

		/**
		 * Instantiates a new resolver type.
		 */
		private ResolverType() {
			this.resolver = null;
		}

		/**
		 * Instantiates a new resolver type.
		 * 
		 * @param resolver
		 *          the resolver
		 */
		private ResolverType(Resolver resolver) {
			this.resolver = resolver;
		}

		/**
		 * Gets the resolver.
		 * 
		 * @return the resolver
		 */
		public final Resolver getResolver() {
			return this.resolver;
		}
	}
	
	/** The Constant RESOLVER_SEARCH_PATH_PROPERTY. */
	public static final String RESOLVER_SEARCH_PATH_PROPERTY =
    "resolver.search.path";

	/**
	 * Can be resolved.
	 * 
	 * @param address
	 *          the address
	 * @return true, if successful
	 */
	public boolean canBeResolved(byte[] address);

	/**
	 * Clear cache.
	 */
	public void clearCache();

	/**
	 * Initialize if needed.
	 */
	public void initializeIfNeeded();

	/**
	 * Checks if is cached.
	 * 
	 * @param address
	 *          the address
	 * @return true, if is cached
	 */
	public boolean isCached(byte[] address);

	/**
	 * Load cache.
	 * 
	 * @param url
	 *          the url
	 * @return the int
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public int loadCache(URL url) throws IOException;

	/**
	 * Resolve.
	 * 
	 * @param address
	 *          the address
	 * @return the string
	 */
	public String resolve(byte[] address);

	/**
	 * Save cache.
	 * 
	 * @return the int
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public int saveCache() throws IOException;
}