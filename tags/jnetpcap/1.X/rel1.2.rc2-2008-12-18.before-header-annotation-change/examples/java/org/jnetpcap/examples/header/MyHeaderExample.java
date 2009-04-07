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
package org.jnetpcap.examples.header;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderScanner;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.header.Ip4;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class MyHeaderExample
    extends JHeader {

	public static int ID;

	public final static JHeaderScanner SCANNER = new JHeaderScanner() {

		@Override
		public int getHeaderLength(JPacket packet, int offset) {
			return 8; // always 8 bytes long
		}

		@Override
		public int getNextHeader(JPacket packet, int offset) {
			/*
			 * For our header, Ip4 always follows it. We can implement any type of
			 * logic we want here, like looking up values in other headers or other
			 * conditions.
			 */
			
			return Ip4.ID;
		}

	};

	static {
		ID = JRegistry.register(MyHeaderExample.class, SCANNER);
		
	}

	/**
	 * @param id
	 * @param name
	 */
	public MyHeaderExample(int id, String name) {
		super(id, name);
	}

}
