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

import java.nio.ByteBuffer;
import java.sql.Time;
import java.util.Properties;

import org.jnetpcap.nio.JMemory.Type;

// TODO: Auto-generated Javadoc
/**
 * The Class JMemoryPool.
 */
public class JMemoryPool {

	/**
	 * The Class Block.
	 */
	public static class Block extends JMemory {

		/** The available. */
		private int available = 0;

		/** The current. */
		private int current = 0;

		/** The created on. */
		private long createdOn;

		/**
		 * Instantiates a new block.
		 * 
		 * @param size
		 *          the size
		 */
		Block(final int size) {
			super(size);
			this.available = size;
			this.createdOn = System.currentTimeMillis();
		}

		/**
		 * Instantiates a new block.
		 * 
		 * @param peer
		 *          the peer
		 */
		Block(final JMemory peer) {
			super(peer);
			this.createdOn = System.currentTimeMillis();
		}

		/**
		 * Allocate.
		 * 
		 * @param size
		 *          the size
		 * @return the int
		 */
		public synchronized int allocate(int size) {

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
		 * Free.
		 * 
		 * @param offset
		 *          the offset
		 * @param length
		 *          the length
		 */
		public void free(final int offset, final int length) {
			// Do nothing for now
		}

		/* (non-Javadoc)
		 * @see java.lang.Object#toString()
		 */
		public String toString() {
			StringBuilder b = new StringBuilder(80);
			b.append("JMemoryPool::Block");
			b.append('[');
			b.append("capacity=").append(size());
			b.append(',');
			b.append("available=").append(this.current);
			b.append(',');
			b.append("createdOn=").append(new Time(this.createdOn).toString());
			b.append(']');

			return b.toString();
		}
	}

	/** The Constant BUS_WIDTH. */
	private final static int BUS_WIDTH = JNumber.Type.INT.size;

	/** The Constant DEFAULT_BLOCK_SIZE. */
	public static final int DEFAULT_BLOCK_SIZE = 32 * 1024;

	/** The default pool. */
	private static JMemoryPool defaultPool;

	/**
	 * Buffer.
	 * 
	 * @param size
	 *          the size
	 * @return the j buffer
	 */
	public static JBuffer buffer(final int size) {
		final JBuffer buffer = new JBuffer(Type.POINTER);
		defaultMemoryPool().allocate(size, buffer);

		return buffer;
	}

	/**
	 * Malloc.
	 * 
	 * @param size
	 *          the size
	 * @param storage
	 *          the storage
	 */
	public static void malloc(final int size, final JMemory storage) {
		defaultMemoryPool().allocate(size, storage);
	}

	/** The block. */
	private Block block;

	/** The block size. */
	private int blockSize;

	/**
	 * Instantiates a new j memory pool.
	 */
	public JMemoryPool() {
		blockSize = getBlockSize();
	}

	/**
	 * Instantiates a new j memory pool.
	 * 
	 * @param defaultBlockSize
	 *          the default block size
	 */
	public JMemoryPool(final int defaultBlockSize) {
		this.blockSize = defaultBlockSize;
	}

	/**
	 * Allocate.
	 * 
	 * @param size
	 *          the size
	 * @param memory
	 *          the memory
	 */
	public synchronized void allocate(final int size, final JMemory memory) {

		final Block block = getBlock(size);
		final int offset = block.allocate(size);

		memory.peer(block, offset, size);
	}

	/**
	 * Allocate exclusive.
	 * 
	 * @param size
	 *          the size
	 * @return the j memory
	 */
	public JMemory allocateExclusive(final int size) {
		return new JMemory(size) {
			// Empty
		};
	}

	/**
	 * Duplicate.
	 * 
	 * @param src
	 *          the src
	 * @param dst
	 *          the dst
	 * @return the int
	 */
	public synchronized int duplicate(JMemory src, JMemory dst) {
		final Block block = getBlock(src.size);
		final int offset = block.allocate(src.size);

		dst.peer(block, offset, src.size);

		return src.size;
	}

	/**
	 * Duplicate2.
	 * 
	 * @param src1
	 *          the src1
	 * @param src2
	 *          the src2
	 * @param dst1
	 *          the dst1
	 * @param dst2
	 *          the dst2
	 * @return the int
	 */
	public synchronized int duplicate2(JMemory src1, JMemory src2, JMemory dst1, JMemory dst2) {
		final int size1 = src1.size;
		final int size2 = src2.size;

		final int size = src1.size + src2.size;

		final Block block = getBlock(size);
		final int offset = block.allocate(size);

		int o = src1.transferTo(block, 0, size1, offset);
		src2.transferTo(block, 0, size2, offset + o);

		dst1.peer(block, offset, size1);
		dst2.peer(block, offset + o, size2);

		return size;
	}

	/**
	 * Duplicate2.
	 * 
	 * @param src1
	 *          the src1
	 * @param src2
	 *          the src2
	 * @param dst1
	 *          the dst1
	 * @param dst2
	 *          the dst2
	 * @return the int
	 */
	public synchronized int duplicate2(JMemory src1,
			ByteBuffer src2,
			JMemory dst1,
			JMemory dst2) {

		final int size1 = src1.size;
		final int size2 = src2.limit() - src2.position();

		final int size = size1 + size2;

		final Block block = getBlock(size);
		final int offset = block.allocate(size);

		int o = src1.transferTo(block, 0, size1, offset);
		block.transferFrom(src2, offset + o);

		dst1.peer(block, offset, size1);
		dst2.peer(block, offset + o, size2);

		return size;
	}

	/**
	 * Duplicate.
	 * 
	 * @param src
	 *          the src
	 * @param dst
	 *          the dst
	 * @return the int
	 */
	public synchronized int duplicate(ByteBuffer src, JMemory dst) {

		final int size = src.limit() - src.position();

		final Block block = getBlock(size);
		final int offset = block.allocate(size);

		block.transferFrom(src, offset);

		dst.peer(block, offset, size);

		return size;
	}

	/**
	 * Gets the block.
	 * 
	 * @param size
	 *          the size
	 * @return the block
	 */
	public Block getBlock(int size) {

		/* Align to an even boundary */
		size += (size % BUS_WIDTH);

		if (this.block == null || this.block.available < size) {
				this.block = newBlock(size);
		}

		return this.block;
	}

	/**
	 * New block.
	 * 
	 * @param atLeastInSize
	 *          the at least in size
	 * @return the block
	 */
	private Block newBlock(final int atLeastInSize) {
		return new Block((atLeastInSize > this.blockSize) ? atLeastInSize
				: this.blockSize);
	}

	/**
	 * Default memory pool.
	 * 
	 * @return the j memory pool
	 */
	public static JMemoryPool defaultMemoryPool() {
		if (defaultPool == null) {
			defaultPool = new JMemoryPool();
		}
		return defaultPool;
	}

	/**
	 * Shutdown.
	 */
	public static void shutdown() {
		if (defaultPool != null) {
			defaultPool.block = null;
			defaultPool = null;
		}
	}

	/**
	 * Gets the block size.
	 * 
	 * @return the block size
	 */
	public int getBlockSize() {
		if (blockSize != 0) {
			return blockSize;
		}
		
		Properties p = System.getProperties();
		String s = p.getProperty("org.jnetsoft.nio.BlockSize");
		s = (s == null) ? p.getProperty("nio.BlockSize") : s;
		s = (s == null) ? p.getProperty("org.jnetsoft.nio.blocksize") : s;
		s = (s == null) ? p.getProperty("nio.blocksize") : s;
		s = (s == null) ? p.getProperty("nio.bs") : s;

		if (s != null) {
			blockSize = (int)JMemory.parseSize(s); // process suffixes kb,mb,gb,tb
		}

		if (blockSize == 0) {
			blockSize = DEFAULT_BLOCK_SIZE;
		}

		return blockSize;
	}

	/**
	 * Sets the block size.
	 * 
	 * @param blockSize
	 *          the new block size
	 */
	public void setBlockSize(int blockSize) {
		this.blockSize = blockSize;
	}

}
