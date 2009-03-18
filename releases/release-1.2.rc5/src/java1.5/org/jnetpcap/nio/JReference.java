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
package org.jnetpcap.nio;

/**
 * A specialized class that is used for managing JNI global object references.
 * Global JNI references once allocated need to be explicitely deallocated or
 * they will always hold on to the the java object reference preventing the
 * objects of ever going out of scope. This class allows a native structure to
 * create and use global JNI references while JReference class keeps track of
 * the created references for deallocation purposes when the time comes.
 * <p>
 * This class is internally maintained by JMemory and the user usually does not
 * have to ever deal with it directly. References are maintained automatically.
 * References objects are transfered during the peering and copy process just
 * like JMemory keeper objects. This makes sure that JNI global references are
 * not released too soon but are when the last object using them is GCed. The
 * references array is a native structure, peered with JReference from JNI
 * space.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JReference
    extends JStruct {

	private static final String STRUCT_NAME = "jni_global_ref_t";

	/**
	 * Default number of space to allocate to hold references. Accessed from JNI.
	 */
	@SuppressWarnings("unused")
  private final static int DEFAULT_REFERENCE_COUNT = 3;

	/**
	 * This type of structure is always allocated natively and peered with a java
	 * counter part.
	 */
	public JReference() {
		super(STRUCT_NAME, Type.POINTER);
	}

	@Override
	protected void cleanup() {
		cleanupReferences();

		super.cleanup();
	}

	/**
	 * Releases any held JNI global references
	 */
	private native void cleanupReferences();
	
	public native String toDebugString();
	
	public native int getCapacity();

}
