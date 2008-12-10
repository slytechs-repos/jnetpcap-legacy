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
 * DIX Ethernet2 definition
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Ethernet
    extends JHeader {

	/**
	 * A table of EtherType values and their names
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum EthernetType {
		IP4(0x800, "ip version 4"),
		IP6(0x86DD, "ip version 6"),
		IEEE_802DOT1Q(0x8100, "vlan - IEEE 802.1q"), ;
		private final int id;

		private final String description;

		private EthernetType(int id) {
			this.id = id;
			this.description = name().toLowerCase();
		}

		private EthernetType(int id, String description) {
			this.id = id;
			this.description = description;

		}

		public static String toString(int id) {
			for (EthernetType t : values()) {
				if (t.id == id) {
					return t.description;
				}
			}

			return null;
		}

		public final int getId() {
			return this.id;
		}

		public final String getDescription() {
			return this.description;
		}

		/**
		 * @param type
		 * @return
		 */
		public static EthernetType valueOf(int type) {
			for (EthernetType t : values()) {
				if (t.id == type) {
					return t;
				}
			}

			return null;
		}

	}

	public static final String NAME = "Ethernet";

	public static final String NICNAME = "Eth";

	public static final String ORG_IEEE = "IEEE Ethernet2";

	public static final int ID = JProtocol.ETHERNET_ID;

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public static final int LENGTH = 14; // Ethernet header is 14 bytes long

	/**
	 * Field objects for JFormatter
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] FIELDS =
	    {
	        new JField(Style.BYTE_ARRAY_DASH_ADDRESS, "destination", "dst",
	            new JStaticField<Ethernet, byte[]>(0, 48) {

		            public byte[] value(Ethernet header) {
			            return header.destination();
		            }

	            }),
	        new JField(Style.BYTE_ARRAY_DASH_ADDRESS, "source", "src",
	            new JStaticField<Ethernet, byte[]>(6, 48) {

		            public byte[] value(Ethernet header) {
			            return header.source();
		            }

	            }),
	        new JField(Style.INT_HEX, "protocol", "type",
	            new JStaticField<Ethernet, Integer>(12, 16) {

		            public Integer value(Ethernet header) {
			            return header.type();
		            }

		            @Override
		            public String valueDescription(Ethernet header) {
			            final String s = EthernetType.toString(header.type());
			            if (s == null) {
				            return super.valueDescription(header);
			            } else {
				            return s;
			            }
		            }

	            }) };

	public Ethernet() {
		super(ID, FIELDS, NAME, NICNAME);
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

	public int type() {
		return getUShort(0 + 12);
	}

	public EthernetType typeEnum() {
		return EthernetType.valueOf(type());
	}

	public void type(int type) {
		setUShort(0 + 12, type);
	}
}