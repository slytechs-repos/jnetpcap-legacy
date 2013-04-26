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
import java.nio.ByteOrder;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import junit.framework.TestCase;

import org.jnetpcap.nio.JNumber.Type;
import org.jnetpcap.packet.PeeringException;

// TODO: Auto-generated Javadoc
/**
 * The Class TestJMemory.
 */
public class TestJMemory extends TestCase {

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	/**
	 * Test peer with non direct byte buffer.
	 */
	public void testPeerWithNonDirectByteBuffer() {
		ByteBuffer b = ByteBuffer.allocate(4);
		JNumber n = new JNumber(Type.INT);

		try {
			n.peer(b);
			fail("expected IllegalArgumentException");
		} catch (Exception e) {
			// SUCCESS
		}
	}

	/**
	 * Test peer with direct byte buffer.
	 * 
	 * @throws PeeringException
	 *             the peering exception
	 */
	public void testPeerWithDirectByteBuffer() throws PeeringException {
		ByteBuffer b = ByteBuffer.allocateDirect(4);
		b.order(ByteOrder.nativeOrder());
		b.putInt(100);
		b.flip();

		JNumber n = new JNumber(Type.INT);
		n.peer(b);

		assertEquals(100, n.intValue());
	}

	/**
	 * Test transfer to direct byte buffer.
	 */
	public void testTransferToDirectByteBuffer() {
		ByteBuffer b = ByteBuffer.allocateDirect(4);
		b.order(ByteOrder.nativeOrder());

		JNumber n = new JNumber(Type.INT);
		n.intValue(100);

		n.transferTo(b);
		b.flip(); // need to flip ByteBuffer's after writting

		assertEquals(100, b.getInt());
	}

	/**
	 * Test transfer from direct byte buffer.
	 */
	public void testTransferFromDirectByteBuffer() {
		ByteBuffer b = ByteBuffer.allocateDirect(4);
		b.order(ByteOrder.nativeOrder());
		b.putInt(100);
		b.flip();

		JNumber n = new JNumber(Type.INT);
		n.transferFrom(b);

		assertEquals(100, n.intValue());

	}

	/**
	 * Test read from uninitialized ptr.
	 */
	public void testReadFromUninitializedPtr() {
		JNumber n = new JNumber(JMemory.Type.POINTER); // Uninitialized ptr

		try {
			assertEquals(100, n.intValue());
			fail("Expected a native NULL ptr exception");

		} catch (NullPointerException e) {
			// expected
		}

	}

	public void testLargeMemoryAllocations() {

		final long timeout = 1000;
		long expire = System.currentTimeMillis() + timeout;

		DisposableGC.getDefault().setVerbose(true);
		final BlockingQueue<JMemory> queue =
				new ArrayBlockingQueue<JMemory>(100000, true);

		Thread consumer = new Thread() {
			public void run() {

				while (true) {
					try {
						queue.take();
//						Thread.sleep(1);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}

			}
		};
		consumer.start();

		final int COUNT = 100000000;
		final int SIZE = 1 * 1024 * 1024;
		long total = 0;
		JMemoryPool pool = new JMemoryPool();
		for (int i = 0; i < COUNT; i++) {
			JMemory memory = new JMemory(JMemory.POINTER) {
			};
			pool.allocate(SIZE, memory);
//			queue.offer(memory);
			total += SIZE;

//			if (System.currentTimeMillis() >= expire) {
//				System.out.printf("size=%dMB queue.size=%d%n",
//						(total) / (1000000),
//						queue.size());
//				expire = System.currentTimeMillis() + timeout;
//			}
		}
	}

}
