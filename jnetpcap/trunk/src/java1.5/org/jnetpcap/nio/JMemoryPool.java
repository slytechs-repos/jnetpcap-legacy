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
 * and automatically using java's garbage collection mechanism.
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
	    extends
	    JMemory {

		/**
		 * How many bytes are available for allocation in this current block
		 */
		private int available = 0;

		/**
		 * Position into the block where the next available byte resides
		 */
		private int current = 0;

		/**
		 * Constructor for allocating a block of a requested size
		 * 
		 * @param size
		 *          number of bytes to allocate for this block
		 */
		Block(final int size) {
			super(size);
			this.available = size;
		}

		/**
		 * Peers this block with another memory object
		 * 
		 * @param peer
		 *          memory object to peer with
		 */
		Block(final JMemory peer) {
			super(peer);
		}

		/**
		 * Allocates requested size number of bytes from existing memory block
		 * 
		 * @param size
		 *          number of bytes
		 * @return offset into the buffer where the allocated memory begins
		 */
		public int allocate(int size) {

			/* Align to an even boundary */
			size += (size % BUS_WIDTH);

			if (size > this.available) {
				return -1;
			}
			final int allocated = this.current;
			this.available -= size;
			this.current += size;

			return allocated;
		}

		/**
		 * Frees the existing memory to be put back in the memory pool.
		 * 
		 * @param offset
		 * @param length
		 */
		public void free(final int offset, final int length) {
			// Do nothing for now
		}

	}

	/**
	 * The size of the native integer which is also the bus-size in bytes of the
	 * hardware architecture. We use the BUS_WIDTH to align our allocated memory
	 * on that boundary.
	 */
	private final static int BUS_WIDTH = JNumber.Type.INT.size;

	/**
	 * Default block size. JMemoryPool allocates memory in a large block which
	 * then further sub allocates per individual requests. The is the default
	 * size.
	 */
	public static final int DEFAULT_BLOCK_SIZE = 1024 * 10;

	private final static JMemoryPool global = new JMemoryPool();

	/**
	 * Allocates requested size of memory from the global memory pool.
	 * 
	 * @param size
	 *          allocation size in bytes
	 * @return buffer which references the allocated memory
	 */
	public static JBuffer buffer(final int size) {
		final JBuffer buffer = new JBuffer(Type.POINTER);
		global.allocate(size, buffer);

		return buffer;
	}

	/**
	 * @param size
	 * @param storage
	 */
	public static void malloc(final int size, final JMemory storage) {
		global.allocate(size, storage);
	}

	/**
	 * Currently active block from which memory allocations take place if its big
	 * enough to fullfil the requests
	 */
	private Block block;

	/**
	 * Current default block size when creating new memory blocks. This is user
	 * modifiable.
	 */
	private int blockSize = DEFAULT_BLOCK_SIZE;

	/**
	 * A pool of blocks that is maintained when a block becomes to small to
	 * fullful an allocation request and a new block is allocated. The too small
	 * block is put in the pool to possibly be reused to fullfil smaller requests
	 */
	private final List<Reference<Block>> pool =
	    new LinkedList<Reference<Block>>();

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
	public JMemoryPool(final int defaultBlockSize) {
		this.blockSize = defaultBlockSize;
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
	public void allocate(final int size, final JMemory memory) {

		final Block block = getBlock(size);
		final int offset = block.allocate(size);

		memory.peer(block, offset, size);
	}

	/**
	 * Gets a block of memory that is big enough to hold at least size number of
	 * bytes. The user must further request from the block
	 * {@link Block#allocate(int)} the size of memory needed. The block will then
	 * return an offset into the memory which has been reserved for this
	 * allocation. The pool of used blocks with potential of some available memory
	 * in them is maintained using a WeakReference. This allows the blocks to be
	 * GCed when no references to them exist, even if there is still a bit of
	 * available memory left in them.
	 * 
	 * @see Block#allocate(int)
	 * @param size
	 *          minimum available amount of memory in a block
	 * @return block big enough to hold size number of bytes
	 */
	public Block getBlock(int size) {

		/* Align to an even boundary */
		size += (size % BUS_WIDTH);

		if (this.block == null) {
			if ((this.block = getFromPool(size)) == null) {
				this.block = newBlock(size);
			}
		} else if (this.block.available < size) {
			this.pool.add(new WeakReference<Block>(this.block));

			if ((this.block = getFromPool(size)) == null) {
				this.block = newBlock(size);
			}
		}

		return this.block;
	}

	/**
	 * Checks if a block resides in the pool that has atleast minimumSize number
	 * of bytes still available.
	 * 
	 * @param minimumSize
	 * @return
	 */
	private Block getFromPool(final int minimumSize) {
		final Iterator<Reference<Block>> i = this.pool.iterator();
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
	 * Creates a new block to be used for memory allocations of atLeast the size
	 * supplied or possibly bigger.
	 * 
	 * @param atLeastInSize
	 *          minimum number of bytes to allocate
	 * @return a new block to be used for allocations
	 */
	private Block newBlock(final int atLeastInSize) {
		return new Block((atLeastInSize > this.blockSize) ? atLeastInSize
		    : this.blockSize);

	}

}
