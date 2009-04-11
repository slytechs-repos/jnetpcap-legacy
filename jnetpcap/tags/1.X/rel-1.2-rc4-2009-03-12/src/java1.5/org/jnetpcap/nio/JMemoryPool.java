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
package org.jnetpcap.nio;

import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.jnetpcap.nio.JMemory.Type;

/**
 * Provides a mechanism for allocating memory to JMemory objects. This class is
 * intended to be used when for example JPacket objects need to be kept around
 * for longer periods of time than a single loop cycle. Since libpcap library
 * utilizes a round-robin memory buffer for returning packet data buffers, this
 * class provides a mechanism for copying that data into more permanent storage
 * very efficiently.
 * <p>
 * The pool works by allocating a memory blocks which are given out to any
 * JMemory class that requests a chunk. That memory is given out, out of the
 * pool, until the block is completely exhausted, then a new block is allocated
 * and continues to give out the memory. The memory blocks are released and
 * deallocated when the last JMemory block that receive any of the memory is
 * garbage collected. When that happens the original memory block is deallocated
 * with a native C free() call. The user does not have to do anything special,
 * the memory management is done completely behind the scene, very efficiently
 * and automatically using.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JMemoryPool {

	/**
	 * A block of native memory allocated with malloc. This block is further sub
	 * allocated on a per request basis using the method {@link #allocate(int)}.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class Block
	    extends JMemory {

		private int available = 0;

		private int current = 0;

		/**
		 * @param size
		 */
		Block(int size) {
			super(size);
			available = size;
		}

		/**
		 * @param peer
		 */
		Block(JMemory peer) {
			super(peer);
		}

		public int allocate(int size) {
			if (size > available) {
				return -1;
			}
			final int allocated = current;
			available -= size;
			current += size;

			return allocated;
		}

		public void free(int offset, int length) {
			// Do nothing for now
		}

	}

	/**
	 * Default block size. JMemoryPool allocates memory in a large block which
	 * then further sub allocates per individual requests. The is the default
	 * size.
	 */
	public static final int DEFAULT_BLOCK_SIZE = 1024 * 10;

	private Block block;

	private List<Reference<Block>> pool = new LinkedList<Reference<Block>>();

	private int blockSize = DEFAULT_BLOCK_SIZE;

	/**
	 * Uses default allocation size and strategy.
	 */
	public JMemoryPool() {
		// Empty
	}

	/**
	 * Allocates blocks in specified size
	 * 
	 * @param defaultBlockSize
	 *          minimum memory block allocation size
	 */
	public JMemoryPool(int defaultBlockSize) {
		this.blockSize = defaultBlockSize;
	}

	/**
	 * Gets a block of memory that is big enough to hold at least size number of
	 * bytes. The user must further request from the block
	 * {@link Block#allocate(int)} the size of memory needed. The block will then
	 * return an offset into the memory which has been reserved for this
	 * allocation
	 * 
	 * @see Block#allocate(int)
	 * @param size
	 *          minimum available amount of memory in a block
	 * @return block big enough to hold size number of bytes
	 */
	public Block getBlock(int size) {
		if (block == null) {
			if ((block = getFromPool(size)) == null) {
				block = newBlock(size);
			}
		} else if (block.available < size) {
			pool.add(new WeakReference<Block>(block));

			if ((block = getFromPool(size)) == null) {
				block = newBlock(size);
			}
		}

		return block;
	}

	/**
	 * @param minimumSize
	 * @return
	 */
	private Block getFromPool(int minimumSize) {
		Iterator<Reference<Block>> i = pool.iterator();
		while (i.hasNext()) {
			final Reference<Block> r = i.next();
			if (r == null) {
				continue;
			}

			final Block b = r.get();
			if (b == null) {
				i.remove();
			} else {
				if (b.available > minimumSize) {
					return b;
				}
			}
		}

		return null;
	}

	/**
	 * @param atLeastInSize
	 * @return
	 */
	private Block newBlock(int atLeastInSize) {
		return new Block((atLeastInSize > blockSize) ? atLeastInSize : blockSize);

	}

	/**
	 * Allocates size bytes of memroy and initializes the supplied memory pointer
	 * class.
	 * 
	 * @param size
	 *          number of bytes
	 * @param memory
	 *          memory pointer
	 */
	public void allocate(int size, JMemory memory) {
		final Block block = getBlock(size);
		final int offset = block.allocate(size);

		memory.peer(block, offset, size);
	}

	private final static JMemoryPool global = new JMemoryPool();

	/**
	 * @param size
	 * @param storage
	 */
	public static void malloc(int size, JMemory storage) {
		global.allocate(size, storage);
	}
	
	/**
	 * @param size
	 * @param storage
	 */
	public static JBuffer buffer(int size) {
		final JBuffer buffer = new JBuffer(Type.POINTER);
		global.allocate(size, buffer);
		
		return buffer;
	}


}
