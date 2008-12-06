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
 * IEEE 802.3 data link header definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class IEEE802dot3
    extends JHeader {

	public static final int ID = JProtocol.IEEE_802DOT3_ID;

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public static final int LENGTH = 14; // 802.3 header is 14 bytes long

	/**
	 * Field objects for JFormatter
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] FIELDS =
	    {
	        new JField(Style.BYTE_ARRAY_DASH_ADDRESS, "destination", "dst",
	            new JStaticField<IEEE802dot3, byte[]>(0, 48) {

		            public byte[] value(IEEE802dot3 header) {
			            return header.destination();
		            }
	            }),

	        new JField(Style.BYTE_ARRAY_DASH_ADDRESS, "source", "src",
	            new JStaticField<IEEE802dot3, byte[]>(6, 48) {

		            public byte[] value(IEEE802dot3 header) {
			            return header.source();
		            }
	            }),

	        new JField("length", "len", new JStaticField<IEEE802dot3, Integer>(
	            12, 16) {

		        public Integer value(IEEE802dot3 header) {
			        return header.length();
		        }
	        }),

	    };

	public IEEE802dot3() {
		super(ID, FIELDS, "802.3", "Eth");
		order(BYTE_ORDER);
	}

	public byte[] destination() {
		return getByteArray(0, 6);
	}

	public byte[] destinationToByteArray(byte[] array) {
		return getByteArray(0, array);
	}

	public void destination(byte[] array) {
		setByteArray(0, array);
	}

	public byte[] source() {
		return getByteArray(0 + 6, 6);
	}

	public void source(byte[] array) {
		setByteArray(0 + 6, array);
	}

	public byte[] sourceToByteArray(byte[] array) {
		return getByteArray(0 + 6, array);
	}

	public int length() {
		return getUShort(0 + 12);
	}

	public void length(int len) {
		setUShort(0 + 12, len);
	}
}