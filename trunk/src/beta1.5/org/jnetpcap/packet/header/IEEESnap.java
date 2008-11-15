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

public class IEEESnap
    extends JHeader {

	public static final int ID = JProtocol.IEEE_SNAP_ID;

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;
	
	/**
	 * Field objects for JFormatter
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] FIELDS =
	    {
	        new JField(Style.LONG_DEC, "oui", "oui",
	            new JStaticField<IEEESnap, Long>(0, 24) {

		            public Long value(IEEESnap header) {
			            return header.oui();
		            }
	            }),

	        new JField("pid", "pid", new JStaticField<IEEESnap, Integer>(0, 16) {

		        public Integer value(IEEESnap header) {
			        return header.pid();
		        }
	        }),

	    };

	public IEEESnap() {
		super(ID, "snap", "snap");
		order(BYTE_ORDER);
	}

	public long oui() {
		return getUInt(0) & 0x00FFFFFF;
	}

	public int pid() {
		return getUShort(3);
	}
}