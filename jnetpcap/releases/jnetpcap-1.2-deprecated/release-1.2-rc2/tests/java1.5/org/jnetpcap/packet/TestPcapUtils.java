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

import org.jnetpcap.packet.format.FormatUtils;


/**
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class TestPcapUtils
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

	public void testIp6AddressConversion() {

		byte[] a = new byte[] {
		    1,
		    2,
		    3,
		    4,
		    5,
		    6,
		    7,
		    8,
		    9,
		    10,
		    11,
		    12,
		    13,
		    14,
		    15,
		    16

		};
		
		System.out.println(FormatUtils.asStringIp6(a, true));

	}
	
	public void testIp6WithMiddleHole() {

		byte[] a = new byte[] {
		    1,
		    2,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    11,
		    12,
		    13,
		    14,
		    15,
		    16

		};
		
		System.out.println(FormatUtils.asStringIp6(a, false));
		System.out.println(FormatUtils.asStringIp6(a, true));

	}

	public void testIp6WithFrontHole() {

		byte[] a = new byte[] {
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    9,
		    10,
		    11,
		    12,
		    13,
		    14,
		    15,
		    16

		};
		
		System.out.println(FormatUtils.asStringIp6(a, false));
		System.out.println(FormatUtils.asStringIp6(a, true));

	}
	
	public void testIp6WithBackHole() {

		byte[] a = new byte[] {
		    9,
		    10,
		    11,
		    12,
		    13,
		    14,
		    15,
		    16,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,

		};
		
		System.out.println(FormatUtils.asStringIp6(a, false));
		System.out.println(FormatUtils.asStringIp6(a, true));

	}

	public void testIp6WithOddHole() {

		byte[] a = new byte[] {
		    9,
		    10,
		    11,
		    12,
		    13,
		    14,
		    15,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,
		    0,

		};
		
		System.out.println(FormatUtils.asStringIp6(a, false));
		System.out.println(FormatUtils.asStringIp6(a, true));

	}


}
