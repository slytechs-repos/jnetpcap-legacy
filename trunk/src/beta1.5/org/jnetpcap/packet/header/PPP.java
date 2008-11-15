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
package org.jnetpcap.packet.header;

import java.nio.ByteOrder;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.format.JField;
import org.jnetpcap.packet.format.JStaticField;
import org.jnetpcap.packet.format.JFormatter.Priority;
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PPP
    extends JHeader {

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public static final int ID = JProtocol.PPP_ID;
	
	/**
	 * Field objects for JFormatter
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] FIELDS =
	    {
	        new JField(Style.INT_DEC, Priority.MEDIUM, "address", "addr",
	            new JStaticField<PPP, Integer>(0, 8) {

		            public Integer value(PPP header) {
			            return header.address();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "control", "control",
	            new JStaticField<PPP, Integer>(1, 8) {

		            public Integer value(PPP header) {
			            return header.control();
		            }
	            }),

	        new JField(Style.INT_HEX, Priority.MEDIUM, "protocol", "type",
	            new JStaticField<PPP, Integer>(2, 16) {

		            public Integer value(PPP header) {
			            return header.protocol();
		            }
	            }),

	    };

	/**
	 * @param id
	 */
	public PPP() {
		super(ID, FIELDS, "ppp", "ppp");
		order(BYTE_ORDER);
	}

	public int address() {
		return getUByte(0);
	}

	public int control() {
		return getUByte(1);
	}

	public int protocol() {
		return getUShort(2);
	}

}
