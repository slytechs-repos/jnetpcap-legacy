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
package org.jnetpcap.packet;

import junit.framework.TestCase;

import org.jnetpcap.packet.JBinding.DefaultJBinding;
import org.jnetpcap.packet.header.Ethernet;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.packet.header.Ip6;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestJRegistry
    extends TestCase {

	/**
	 * A test class that simplifies creation of test bindings by not having it
	 * abstract :)
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class TestBinding
	    extends DefaultJBinding {

		/**
		 * @param myId
		 * @param targetId
		 * @param dependencyIds
		 */
		public TestBinding(int myId, int targetId, int... dependencyIds) {
			super(myId, targetId, dependencyIds);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JBinding#checkLength(org.jnetpcap.packet.JPacket,
		 *      int)
		 */
		public int checkLength(JPacket packet, int offset) {
			throw new UnsupportedOperationException("Not implemented yet");
		}

	};

	private JRegistry registry;

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		registry = new JRegistry();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		registry = null;
	}

	public void testCoreProtocolRegistrationByJProtocol() {

		for (JProtocol p : JProtocol.values()) {
			assertEquals(p.ID, registry.lookupId(p));
		}
	}

	public void testCoreProtocolRegistrationByClass() {

		for (JProtocol p : JProtocol.values()) {
			assertEquals(p.ID, registry.lookupId(p.clazz));
		}
	}

	public void testCoreProtocolRegistrationByName() {

		assertEquals(Ethernet.ID, registry.lookupId(Ethernet.class));
		assertEquals(Ip4.ID, registry.lookupId(Ip4.class));
		assertEquals(Ip6.ID, registry.lookupId(Ip6.class));
	}

	public void testSetOneSourceBinding() {

		registry
		    .setBindings(new TestBinding(Ip4.ID/* source */, Ethernet.ID/* target */));

		JBinding[][] bindings = registry.getBindingsBySource();

		assertNotNull(bindings[Ip4.ID]);
		assertNotNull(bindings[Ip4.ID][0]);
		assertEquals(Ip4.ID, bindings[Ip4.ID][0].getId());
		assertEquals(Ethernet.ID, bindings[Ip4.ID][0].getTargetId());

	}

	public void testSetOneTargetBinding() {

		registry
		    .setBindings(new TestBinding(Ip4.ID/* source */, Ethernet.ID/* target */));

		JBinding[][] bindings = registry.getBindingsByTarget();

		assertNotNull(bindings[Ethernet.ID]);
		assertNotNull(bindings[Ethernet.ID][0]);
		assertEquals(Ip4.ID, bindings[Ethernet.ID][0].getId());
		assertEquals(Ethernet.ID, bindings[Ethernet.ID][0].getTargetId());

	}

	public void testSetBindingOutOfBoundHi() {

		try {
			registry
			    .setBindings(new TestBinding(10000/* source */, Ethernet.ID/* target */));
			fail("Expected IndexOutOfBoundsException");
		} catch (IndexOutOfBoundsException e) {
			// Success
		}
	}

	public void testSetBindingOutOfBoundLow() {

		try {
			registry
			    .setBindings(new TestBinding(-1/* source */, Ethernet.ID/* target */));
			fail("Expected IndexOutOfBoundsException");
		} catch (IndexOutOfBoundsException e) {
			// Success
		}
	}

	public void testSetBindingAtIndexZero() {

		try {
			registry
			    .setBindings(new TestBinding(0/* source */, Ethernet.ID/* target */));
		} catch (IndexOutOfBoundsException e) {
			fail("Did not expected IndexOutOfBoundsException");
		}
	}

	public void testSetBindingAtMaxIndex() {

		try {
			registry
			    .setBindings(new TestBinding(JRegistry.MAX_ID_COUNT, Ethernet.ID));
			fail("Expected IndexOutOfBoundsException");
		} catch (IndexOutOfBoundsException e) {
			// Success
		}
	}

	public void testSetBindingAtMaxIndexMinusOne() {

		try {
			registry.setBindings(new TestBinding(JRegistry.MAX_ID_COUNT - 1,
			    Ethernet.ID));
		} catch (IndexOutOfBoundsException e) {
			fail("Did not expected IndexOutOfBoundsException");
		}
	}

	public void testBidningsForAllCoreProtocolsBoundToSingle() {

		for (JProtocol p : JProtocol.values()) {
			registry.setBindings(new TestBinding(p.ID, Ethernet.ID));
		}
	}
	
	public void testMultBidningsForAllCoreProtocolsBoundToSingle() {

		final int COUNT = 100;
		
		for (JProtocol p : JProtocol.values()) {
			for (int i = 0; i < COUNT ; i ++) {
				registry.setBindings(new TestBinding(p.ID, Ethernet.ID));
			}
		}
	}

	
	public void testBidningsForAllCoreProtocolsBoundToPrevious() {

		for (JProtocol p : JProtocol.values()) {
			registry.setBindings(new TestBinding(p.ID, ((p.ID == 0)?0:p.ID-1)));
		}
	}
	
	public void testMultBidningsForAllCoreProtocolsBoundToPrevious() {

		final int COUNT = 100;
		
		for (JProtocol p : JProtocol.values()) {
			for (int i = 0; i < COUNT ; i ++) {
				registry.setBindings(new TestBinding(p.ID, ((p.ID == 0)?0:p.ID-1)));
			}
		}
	}



}
