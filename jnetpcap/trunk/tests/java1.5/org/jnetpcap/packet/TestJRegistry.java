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

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.header.BindNetworkFamily;
import org.jnetpcap.header.MyHeader;
import org.jnetpcap.packet.JBinding.DefaultJBinding;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Scanner;
import org.jnetpcap.packet.structure.AnnotatedBindMethod;
import org.jnetpcap.packet.structure.AnnotatedBinding;
import org.jnetpcap.packet.structure.AnnotatedHeaderLengthMethod;
import org.jnetpcap.packet.structure.HeaderDefinitionError;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;


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

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JBinding#getSourceId()
		 */
		public int getSourceId() {
			// TODO Auto-generated method stub
			throw new UnsupportedOperationException("Not implemented yet");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.JBinding#isBound(org.jnetpcap.packet.JPacket,
		 *      int)
		 */
		public boolean isBound(JPacket packet, int offset) {
			// TODO Auto-generated method stub
			throw new UnsupportedOperationException("Not implemented yet");
		}

	};

	private List<HeaderDefinitionError> errors =
	    new ArrayList<HeaderDefinitionError>();

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {

		/*
		 * Now reset error list and clear all the caches from all the relavent
		 * classes for our tests. For our tests we want all the classes to always do
		 * their annotation inspection instead of doing it once and caching it.
		 */
		errors.clear();
		AnnotatedBinding.clearCache();
		AnnotatedBindMethod.clearCache();
		AnnotatedHeaderLengthMethod.clearCache();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		if (errors.isEmpty() == false) {
			System.out.println("Found errors:");

			for (HeaderDefinitionError e : errors) {
				System.out.println(e.getMessage());
			}

			fail("Found " + errors.size() + " header definition errors");
		}
	}

	public void testCoreProtocolRegistrationByJProtocol()
	    throws UnregisteredHeaderException {

		for (JProtocol p : JProtocol.values()) {
			assertEquals(p.getId(), JRegistry.lookupId(p));
		}
	}

	public void testCoreProtocolRegistrationByClass()
	    throws UnregisteredHeaderException {

		System.out.println(JRegistry.toDebugString());

		for (JProtocol p : JProtocol.values()) {
			assertEquals(p.getId(), JRegistry.lookupId(p.getHeaderClass()));
		}
	}

	public void testCoreProtocolRegistrationByName()
	    throws UnregisteredHeaderException {

		assertEquals(Ethernet.ID, JRegistry.lookupId(Ethernet.class));
		assertEquals(JProtocol.IP4_ID, JRegistry.lookupId(Ip4.class));
		assertEquals(Ip6.ID, JRegistry.lookupId(Ip6.class));
	}

	public void testExtractBindingFromJHeader() {
		AnnotatedBinding.inspectJHeaderClass(MyHeader.class, errors);
	}

	public void testJHeaderAnnotatedBindingWithPacket() {
		JBinding[] bindings =
		    AnnotatedBinding.inspectJHeaderClass(MyHeader.class, errors);
		JBinding bindEthernet = bindings[0];
		System.out.println(bindEthernet.toString());

		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		assertTrue("ethernet binding", bindEthernet.isBound(packet, 0));
	}

	public void testAllClassAnnotatedBindingWithPacket() {
		JBinding[] bindings =
		    AnnotatedBinding.inspectClass(BindNetworkFamily.class, errors);

		assertTrue("no bindings found", bindings.length > 0);
		JBinding bindEthernet = bindings[0];

		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		System.out.println(bindEthernet.toString());
		assertTrue(bindEthernet.toString(), bindEthernet.isBound(packet, 0));

	}

	@SuppressWarnings("unused")
	private static class TestBindings {
		@Bind(from = Ip4.class, to = Ethernet.class)
		public static boolean bindIp4ToEthernet(JPacket packet, Ethernet eth) {
			return eth.type() == 0x800;
		}

	};

	@SuppressWarnings("unused")
	private static class TestHeader
	    extends JHeader {

		@Field(offset = 0, length = 8)
		public int field1() {
			return super.getUByte(0);
		}

		@Field(offset = 8)
		public int field2() {
			return super.getUByte(0);
		}

		@Dynamic(Field.Property.LENGTH)
		public int field2Length() {
			return field1() * 8;
		}
	}

	public void testAnnonymousBinding() {

		new AbstractBinding<Ethernet>(Ip4.class, Ethernet.class) {

			@Override
			public boolean isBound(JPacket packet, Ethernet header) {
				return header.type() == 0x800;
			}

		};

		Object o = new Object() {

			@SuppressWarnings("unused")
			@Bind(from = Ip4.class, to = Ethernet.class)
			public boolean bindIp4ToEthernet(JPacket packet, Ethernet ethernet) {
				return ethernet.type() == 0x800;
			}
		};
		AnnotatedBinding.inspectObject(o, errors);
	}

	public void testRegistryDump() throws RegistryHeaderErrors {
		JRegistry.register(MyHeader.class);

		JRegistry.lookupId(MyHeader.class);

		Object o = new Object() {

			@SuppressWarnings("unused")
			@Bind(from = Ip4.class, to = MyHeader.class)
			public boolean bindIp4ToMyHeader(JPacket packet, MyHeader my) {
				return my.type() == 0x800;
			}

			@SuppressWarnings("unused")
			@Scanner(Ip4.class)
			public void scanIp4(JScan scan) {

			}
		};

		JRegistry.addBindings(o);
		JRegistry.setScanners(o);
		System.out.println(JRegistry.toDebugString());

		JRegistry.clearScanners(o);
		System.out.println(JRegistry.toDebugString());
	}

}
