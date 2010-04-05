/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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

import org.jnetpcap.packet.JBinding;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.TestUtils;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Bug_PPPoE
    extends
    TestUtils {

	public final static String FILE =
	    "C:\\Documents and Settings\\markbe.DESKTOP-HP.000\\My Documents\\Sly Techs\\Support\\Puneetkhanal\\tcppackets.pcap";

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

	@Header(length = 8)
	public static class MyPPPoE
	    extends
	    JHeader {

		@Bind(to = Ethernet.class)
		public static boolean bindToEthernet(JPacket packet, Ethernet eth) {
			return eth.type() == 0x8864;
		}

//		@Bind(to = MyPPPoE.class, from = Ip4.class)
//		public static boolean bindIp4ToMyPPPoE(JPacket packet, MyPPPoE p) {
//			
//			System.out.printf("bindIp4ToMyPPPoE() nextId()==0x%X\n", p.nextId());
//			return p.nextId() == 0x21;
//		}

		@Field(offset = 0, length = 4)
		public int version() {
			return getUByte(0) & 0x0F;
		}

		@Field(offset = 4, length = 4)
		public int type() {
			return (getUByte(0) & 0xF0) >> 4;
		}

		@Field(offset = 1 * BYTE, length = 1 * BYTE)
		public int code() {
			return getUByte(1);
		}

		@Field(offset = 2 * BYTE, length = 2 * BYTE)
		public int sessionId() {
			return getUShort(2);
		}

		@Field(offset = 4 * BYTE, length = 2 * BYTE)
		public int length() {
			return getUShort(4);
		}

		@Field(offset = 6 * BYTE, length = 2 * BYTE, format="%x")
		public int nextId() {
			return getUShort(6);
		}
	};

	public void test1PPPoE() throws RegistryHeaderErrors {

		final int myId = JRegistry.register(MyPPPoE.class);
		
		JRegistry.addBindings(new JBinding[] {
				new JBinding.DefaultJBinding(Ip4.ID, myId) {

					public int getSourceId() {
	          return getId();
          }

					private final MyPPPoE my = new MyPPPoE();
					public boolean isBound(JPacket packet, int offset) {
	          return packet.hasHeader(my) && my.nextId() == 0x21;
          }
					
				}
		});

		System.out.println(JRegistry.toDebugString());
		PcapPacket packet = super.getPcapPacket(FILE, 1 - WIRESHARK_INDEX);

		System.out.println(packet);
	}
}
