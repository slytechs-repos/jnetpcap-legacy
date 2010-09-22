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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import junit.framework.TestCase;

import org.jnetpcap.nio.JNumber.Type;
import org.jnetpcap.packet.PeeringException;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestJMemory
    extends TestCase {

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

	public void testPeerWithDirectByteBuffer() throws PeeringException {
		ByteBuffer b = ByteBuffer.allocateDirect(4);
		b.order(ByteOrder.nativeOrder());
		b.putInt(100);
		b.flip();

		JNumber n = new JNumber(Type.INT);
		n.peer(b);

		assertEquals(100, n.intValue());
	}

	public void testTransferToDirectByteBuffer() {
		ByteBuffer b = ByteBuffer.allocateDirect(4);
		b.order(ByteOrder.nativeOrder());

		JNumber n = new JNumber(Type.INT);
		n.intValue(100);

		n.transferTo(b);
		b.flip(); // need to flip ByteBuffer's after writting

		assertEquals(100, b.getInt());
	}

	public void testTransferFromDirectByteBuffer() {
		ByteBuffer b = ByteBuffer.allocateDirect(4);
		b.order(ByteOrder.nativeOrder());
		b.putInt(100);
		b.flip();

		JNumber n = new JNumber(Type.INT);
		n.transferFrom(b);

		assertEquals(100, n.intValue());

	}

	public void testReadFromUninitializedPtr() {
		JNumber n = new JNumber(JMemory.Type.POINTER); // Uninitialized ptr

		try {
			assertEquals(100, n.intValue());
			fail("Expected a native NULL ptr exception");

		} catch (NullPointerException e) {
			// expected
		}

	}

}
