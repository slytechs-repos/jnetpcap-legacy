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
package org.jnetsoft.library;

import java.util.Arrays;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class Library {

	/**
	 * Method to actuall load the library and post process more meaningfull error
	 * messages if neccessary
	 * 
	 * @param name
	 *          native library (not extensions or directory paths)
	 * @param dependencies
	 *          a list of names of the libraries this library is depedent on
	 * @throws UnsatisfiedLinkError
	 *           if library is not found or if native linker is unable to resolve
	 *           an object symbol
	 */
	public static void loadLibrary(String name, String... dependencies)
	    throws UnsatisfiedLinkError {
		try {
			System.loadLibrary(name);
		} catch (UnsatisfiedLinkError e) {
			String msg = e.getMessage();

			if (msg.contains("dependent libraries")) {
				throw new UnsatisfiedLinkError(name
				    + " native library is found, but needs "
				    + Arrays.asList(dependencies) + " library(ies) installed first.");
			}

			if (msg.contains("specified procedure")) {
				throw new UnsatisfiedLinkError("Dependency version mismatch: " + name
				    + " library is found, but can't find a required native function"
				    + " call it is dependent on. Make sure all dependencies at the"
				    + " right version levels are installed.");
			}

			if (msg.contains("java.library.path")) {
				throw new UnsatisfiedLinkError(name + " native library is not found. "
				    + "Make sure its installed in /usr/lib or /usr/lib64 or "
				    + "\\windows\\system32 or \\widows\\system64 or "
				    + "set JVM -Djava.library.path=<dir_path_jnetpcap_library> to "
				    + "its location.");
			}

			throw e;
		}

	}

	private Library() {
		// Empty
	}
}
