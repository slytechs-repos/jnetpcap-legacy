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
import org.jnetpcap.packet.format.JFormatter.Style;

/**
 * IEEE Vlan header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class IEEE802dot1q
    extends JHeader {

	public static final int ID = JProtocol.IEEE_802DOT1Q_ID;

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	/**
	 * Field objects for JFormatter
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] FIELDS =
	    {
	        new JField("priority", "pri",
	            new JStaticField<IEEE802dot1q, Integer>(0, 3) {

		            public Integer value(IEEE802dot1q header) {
			            return header.priority();
		            }
	            }),
	        new JField("cfi", "cfi",
	            new JStaticField<IEEE802dot1q, Integer>(0, 1) {

		            public Integer value(IEEE802dot1q header) {
			            return header.cfi();
		            }
	            }),

	        new JField("id", "id",
	            new JStaticField<IEEE802dot1q, Integer>(0, 12) {

		            public Integer value(IEEE802dot1q header) {
			            return header.id();
		            }
	            }),
	        new JField(Style.INT_HEX, "type", "type",
	            new JStaticField<IEEE802dot1q, Integer>(2, 16) {

		            public Integer value(IEEE802dot1q header) {
			            return header.type();
		            }
	            }),

	    };

	public IEEE802dot1q() {
		super(ID, FIELDS, "802.1q", "vlan");
		order(BYTE_ORDER);
	}

	public int priority() {
		return (getUByte(0) & 0xE0) >> 5;
	}

	public int cfi() {
		return (getUByte(0) & 0x10) >> 4;
	}

	public int id() {
		return getUShort(0) & 0x0FFF;
	}

	public int type() {
		return getUShort(2);
	}
}