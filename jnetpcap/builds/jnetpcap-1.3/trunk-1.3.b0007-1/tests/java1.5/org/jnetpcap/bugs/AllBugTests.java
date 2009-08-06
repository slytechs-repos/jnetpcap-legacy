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
package org.jnetpcap.bugs;

import junit.framework.Test;
import junit.framework.TestSuite;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class AllBugTests {

	/**
	 * Run all the bugs
	 * 
	 * @return test
	 */
	public static Test suite() {

		TestSuite suite = new TestSuite("Test for org.jnetpcap.bugs");
		// $JUnit-BEGIN$
		suite.addTestSuite(Bug2827356_PcapPacketHandler_Fails.class);
		suite.addTestSuite(Bug2818101_RtpHeaderLength_Invalid.class);
		suite.addTestSuite(Bug2828030_wirelen_not_set_in_JMemoryPacket.class);
		suite.addTestSuite(Bug2832692_null_ptr_in_hasHeader.class);
		// $JUnit-END$
		return suite;
	}
}
