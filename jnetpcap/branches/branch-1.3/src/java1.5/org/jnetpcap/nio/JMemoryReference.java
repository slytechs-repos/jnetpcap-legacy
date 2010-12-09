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
package org.jnetpcap.nio;

// TODO: Auto-generated Javadoc
/**
 * The Class JMemoryReference.
 */
public class JMemoryReference extends DisposableReference {

	/** The address. */
	long address;
	
	/** The size. */
	long size;

	/**
	 * Instantiates a new j memory reference.
	 * 
	 * @param referant
	 *          the referant
	 * @param address
	 *          the address
	 * @param size
	 *          the size
	 */
	public JMemoryReference(Object referant, long address, long size) {
		super(referant);
		this.address = address;
		this.size = size;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.Disposable#dispose()
	 */
	@Override
	public void dispose() {
		disposeNative(size);
	}

	/**
	 * Dispose native.
	 * 
	 * @param size
	 *          the size
	 */
	protected void disposeNative(long size) {
		disposeNative0(address, size);
	}
	
	/**
	 * Dispose native0.
	 * 
	 * @param address
	 *          the address
	 * @param size
	 *          the size
	 */
	private native void disposeNative0(long address, long size);

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.nio.DisposableReference#remove()
	 */
	@Override
	public void remove() {
		address = 0L;
		size = 0L;
		super.remove();
	}

	/* (non-Javadoc)
	 * @see org.jnetpcap.nio.DisposableReference#size()
	 */
	@Override
	public int size() {
		return (int) size;
	}
	
	

}
