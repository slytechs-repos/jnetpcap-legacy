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
		public int scanForNextHeader(JPacket packet, int offset) {
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

	public void testCoreProtocolRegistrationByJProtocol() throws UnregisteredHeaderException {

		for (JProtocol p : JProtocol.values()) {
			assertEquals(p.ID, JRegistry.lookupId(p));
		}
	}

	public void testCoreProtocolRegistrationByClass() throws UnregisteredHeaderException {

		for (JProtocol p : JProtocol.values()) {
			assertEquals(p.ID, JRegistry.lookupId(p.clazz));
		}
	}

	public void testCoreProtocolRegistrationByName() throws UnregisteredHeaderException {

		assertEquals(Ethernet.ID, JRegistry.lookupId(Ethernet.class));
		assertEquals(Ip4.ID, JRegistry.lookupId(Ip4.class));
		assertEquals(Ip6.ID, JRegistry.lookupId(Ip6.class));
	}



}
