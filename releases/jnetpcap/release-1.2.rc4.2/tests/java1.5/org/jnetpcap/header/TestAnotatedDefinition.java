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
package org.jnetpcap.header;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.JSubHeader;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.format.JFormatter;
import org.jnetpcap.packet.format.TextFormatter;
import org.jnetpcap.packet.format.JFormatter.Detail;
import org.jnetpcap.packet.header.Ethernet;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.packet.structure.AnnotatedBindMethod;
import org.jnetpcap.packet.structure.AnnotatedBinding;
import org.jnetpcap.packet.structure.AnnotatedField;
import org.jnetpcap.packet.structure.AnnotatedHeader;
import org.jnetpcap.packet.structure.AnnotatedHeaderLengthMethod;
import org.jnetpcap.packet.structure.DefaultField;
import org.jnetpcap.packet.structure.HeaderDefinitionError;
import org.jnetpcap.packet.structure.JField;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestAnotatedDefinition
    extends TestCase {

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

	public void _test1() {

		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		MyHeader my = new MyHeader();

		if (packet.hasHeader(my) && my.version() == 4) {
			System.out.printf("found it id=%d\n", my.getId());

			System.out.println(packet.toString());
		} else {
			System.out.printf("not found id=%d\n", my.getId());
		}
	}

	@Header
	public static class TestHeader
	    extends JHeader {

		@HeaderLength
		public static int headerLength(JBuffer buffer, int offset) {
			return Ethernet.LENGTH;
		}

		@Field(offset = 0, length = 16)
		public int fieldA() {
			return getUShort(12);
		}

		@Field(offset = 0, length = 16)
		public int fieldB() {
			return getUShort(12);
		}

		@Dynamic(field = "fieldB_Sub1", value = Field.Property.CHECK)
		public boolean hasFieldB_Sub1() {
			return true;
		}

		@Dynamic(field = "fieldB_Sub1", value = Field.Property.LENGTH)
		public int fieldB_Sub1Length() {
			return 1;
		}

		@Field(parent = "fieldB", offset = 0)
		public int fieldB_Sub1() {
			return getUByte(12);
		}
	}

	@Header(length = 40, id = 0)
	public static class TestSubHeader
	    extends JHeader {

		@Header(length = 30)
		public static class Sub1
		    extends JSubHeader<TestSubHeader> {

			public static class Sub2
			    extends Sub1 {

				@Header(id = 1)
				public static class Sub3
				    extends Sub2 {

					@HeaderLength
					public static int len(JBuffer buffer, int offset) {
						return 01;
					}
				}
			}
		}
	}

	public void test2() {

		AnnotatedHeader ah1 =
		    AnnotatedHeader.inspectJHeaderClass(TestSubHeader.Sub1.Sub2.Sub3.class,
		        errors);

		AnnotatedHeader ah2 =
		    AnnotatedHeader.inspectJHeaderClass(TestSubHeader.Sub1.Sub2.Sub3.class,
		        errors);

		assertTrue(ah1 == ah2); // Check if cached properly

	}

	public void testWithMyHeader() {
		@SuppressWarnings("unused")
    AnnotatedHeader ah1 =
		    AnnotatedHeader.inspectJHeaderClass(MyHeader.class, errors);

	}

	public void testIp4() throws IOException {
		AnnotatedHeader ah1 =
		    AnnotatedHeader.inspectJHeaderClass(Ip4.class, errors);

		AnnotatedField[] afs = ah1.getFields();
		JField[] fields = DefaultField.fromAnnotatedFields(afs);

		for (JField field : fields) {
			System.out.printf("field=%s\n", field.toString());
		}

		Ip4 ip = new Ip4();

		JPacket packet = TestUtils.getPcapPacket("tests/test-afs.pcap", 0);

		if (packet.hasHeader(JProtocol.IP4_ID)) {
			ip = packet.getHeader(ip);
			JFormatter out = new TextFormatter(System.out);
			out.format(ip, Detail.MULTI_LINE_FULL_DETAIL);
		}

	}
}
