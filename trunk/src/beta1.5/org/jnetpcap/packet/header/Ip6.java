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

public class Ip6
    extends JHeader {

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public static final int ID = JProtocol.IP6_ID;

	public static final int LENGTH = 40;

	/**
	 * Field objects for JFormatter
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] FIELDS =
	    {

	        new JField(Style.INT_DEC, Priority.MEDIUM, "version", "ver",
	            new JStaticField<Ip6, Integer>(0, 4) {

		            public Integer value(Ip6 header) {
			            return header.version();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "class", "class",
	            new JStaticField<Ip6, Integer>(0, 12) {

		            public Integer value(Ip6 header) {
			            return header.trafficClass();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "flow", "flow",
	            new JStaticField<Ip6, Integer>(1, 24) {

		            public Integer value(Ip6 header) {
			            return header.flowLabel();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "length", "len",
	            new JStaticField<Ip6, Integer>(4, 16) {

		            public Integer value(Ip6 header) {
			            return header.length();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "next", "type",
	            new JStaticField<Ip6, Integer>(6, 8) {

		            public Integer value(Ip6 header) {
			            return header.next();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "source", "src",
	            new JStaticField<Ip6, byte[]>(8, 128) {

		            public byte[] value(Ip6 header) {
			            return header.source();
		            }
	            }),

	        new JField(Style.INT_DEC, Priority.MEDIUM, "destination", "dst",
	            new JStaticField<Ip6, byte[]>(24, 128) {

		            public byte[] value(Ip6 header) {
			            return header.destination();
		            }
	            }),

	    };

	public Ip6() {
		super(ID, FIELDS, "ip6", "ip6");
		super.order(BYTE_ORDER);
	}

	public int version() {
		return getUByte(0) >> 4;
	}

	public int trafficClass() {
		return getUShort(0) & 0x0FFF;
	}

	public int flowLabel() {
		return getInt(0) & 0x000FFFFF; // We drop the sign bits anyway
	}

	public int length() {
		return getUShort(4);
	}

	public int next() {
		return getUByte(6);
	}

	public int hopLimit() {
		return getUByte(7);
	}

	public byte[] source() {
		return getByteArray(8, 16);
	}

	public byte[] sourceToByteArray(byte[] address) {
		if (address.length != 16) {
			throw new IllegalArgumentException("address must be 16 byte long");
		}
		return getByteArray(8, address);
	}

	public byte[] destination() {
		return getByteArray(24, 16);
	}

	public byte[] destinationToByteArray(byte[] address) {
		if (address.length != 16) {
			throw new IllegalArgumentException("address must be 16 byte long");
		}
		return getByteArray(24, address);
	}

}