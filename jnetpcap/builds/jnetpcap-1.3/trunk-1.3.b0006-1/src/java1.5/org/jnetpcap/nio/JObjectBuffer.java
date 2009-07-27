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

import java.nio.ByteBuffer;

import org.jnetpcap.util.Offset;


/**
 * A special buffer that also allows java object references to be set within the
 * buffer's memory. At JNI level, global JNI references are created and this
 * buffer will keep track of them, to be released when this buffer is released.
 * References are setup to work at JMemory level and will be transfered to other
 * objects if a peer or transfer method is used.
 * <p>
 * JObjectBuffer does not keep track of which reference is set at which memory
 * location within this buffer. Therefore it is impossible to release a
 * individual JNI global reference.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JObjectBuffer
    extends JBuffer {
	
	/**
	 * Size of JNI's jobject reference in bytes. 
	 */
	public final static int REF = sizeofJObject();

	/**
	 * @param type
	 */
	public JObjectBuffer(Type type) {
		super(type);
	}

	/**
	 * @param peer
	 */
	public JObjectBuffer(ByteBuffer peer) {
		super(peer);
	}

	/**
	 * @param size
	 */
	public JObjectBuffer(int size) {
		super(size);
	}

	/**
	 * @param peer
	 */
	public JObjectBuffer(JMemory peer) {
		super(peer);
	}

	/**
	 * @param data
	 */
	public JObjectBuffer(byte[] data) {
		super(data);
	}
	
	/**
	 * Retrieves a jobject reference from the specified memory location.
	 * 
	 * @param <T>
	 * @param c
	 * @param offset
	 * @return
	 */
	public <T> T getObject(Class<T> c, Offset offset) {
		return getObject(c, offset.offset());
	}


	/**
	 * Retrieves a jobject reference from the specified memory location.
	 * 
	 * @param <T>
	 * @param c
	 * @param offset
	 * @return
	 */
	public native <T> T getObject(Class<T> c, int offset);

	/**
	 * Sets the jobject reference at specified location within the buffer. The
	 * buffer will keep track of the global JNI object reference that is created
	 * and it will be deallocated when this object buffer is released.
	 * 
	 * @param <T>
	 * @param value
	 */
	public native <T> void setObject(int offset, T value);
	
	/**
	 * Sets the jobject reference at specified location within the buffer. The
	 * buffer will keep track of the global JNI object reference that is created
	 * and it will be deallocated when this object buffer is released.
	 * 
	 * @param <T>
	 * @param value
	 */
	public <T> void setObject(Offset offset, T value) {
		setObject(offset.offset(), value);
	}


	/**
	 * Returns the native size of JNI's jobject type. sizeof(jobject)
	 * 
	 * @return
	 */
	public native static int sizeofJObject();
}
