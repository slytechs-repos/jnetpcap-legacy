/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.compatibility;

import org.jnetsoft.library.Library;

/**
 * Helper class which loads the main jnetpcap native library. The class is used
 * to manage loading of the main jnetpcap library which contains all of the
 * pcap_* calls starting with version libpcpa 0.8.0. In addition to libpcap
 * calls, the library also contains various jnetpcap specific calls such as the
 * native decoder, protocols and utilities. This is an essential library that
 * jnetpcap can not work without. Therefore if any errors are encountered while
 * the library is loading, its considered a critical error and the
 * {@link java.lang.UnsatisfiedLinkError} exception is thrown from the static
 * initializer, causing JVM to abort loading this class.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class Pcap080 {

	/**
	 * Flag which indicates if the native library, implementing Funct API (API
	 * defined as of libpcap 0.8.0), loaded successfully
	 */
	public final static boolean IS_LOADED;

	/**
	 * Name of the native library. The name is without library postfix which is
	 * not portable between different operating systems (i.e. dll for windows and
	 * so for *NIX.)
	 */
	public final static String LIBRARY_NAME = "jnetpcap";

	/**
	 * Error exception if the library failed to load successfully
	 */
	public final static UnsatisfiedLinkError LOAD_EXCEPTION;

	/**
	 * Message constants that is never null, even when there was not error on
	 * library load. This constant is suitable to be used with jUnit assert
	 * functions since its never null and can be used as the message part of the
	 * assert function.
	 */
	public final static String LOAD_EXCEPTION_MESSAGE;

	static {

		UnsatisfiedLinkError error = null;

		/*
		 * We try and load the libpcap 0.8.0 API library.
		 */
		try {
			Library.loadLibrary(LIBRARY_NAME, "libpcap");

		} catch (UnsatisfiedLinkError e) {
			error = e;
		}

		if (error == null) {
			IS_LOADED = true;
			LOAD_EXCEPTION = null;
			LOAD_EXCEPTION_MESSAGE = "";
		} else {
			IS_LOADED = false;
			LOAD_EXCEPTION = error;
			LOAD_EXCEPTION_MESSAGE = error.getMessage();
		}
	}

	private Pcap080() {
		// Empty
	}
}
