/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.protocol.lan;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.protocol.network.Ip4;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestLan
    extends
    TestUtils {

	public final static String SLL =
	    "C:\\Documents and Settings\\markbe.DESKTOP-HP.000" +
	    "\\My Documents\\Downloads\\CaptureDemo.cap";

	public void testSLL() {
		SLL sll = new SLL();
//		JRegistry.addBindings(new Object() {
//			 @Bind(from = Ip4.class, to = SLL.class)
//			 public boolean bindIp4ToSLL(JPacket packet, SLL sll) {
//			 return sll.type() == 0x800;
//			 }
//
//		});
		System.out.println(super.getPcapPacket(SLL, 1 - 1));
	}

}
