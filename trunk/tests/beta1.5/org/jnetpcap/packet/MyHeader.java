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

import org.jnetpcap.packet.JBinding.DefaultJBinding;
import org.jnetpcap.packet.header.Ip4;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class MyHeader
    extends JHeader {

	public final static int LENGTH = 10;

	public final static int ID = JRegistry.register(MyHeader.class);
	
	public MyHeader() {
		super(ID, "MyHeader");
	}

	public final static JBinding[] BINDINGS =
	    { new DefaultJBinding(MyHeader.ID, Ip4.ID) {
		    private Ip4 ip4 = new Ip4();

		    public int checkLength(JPacket packet, int offset) {
			    return (packet.hasHeader(ip4) && ip4.type() == 0x17) ? packet
			        .remaining(offset, MyHeader.LENGTH) : HEADER_NOT_FOUND;
		    }
	    }

	    };
}
