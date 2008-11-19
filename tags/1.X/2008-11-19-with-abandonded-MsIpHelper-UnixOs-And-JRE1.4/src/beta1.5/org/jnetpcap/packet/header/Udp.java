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

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Udp
    extends JHeader {

	public static final ByteOrder BYTE_ORDER = ByteOrder.BIG_ENDIAN;

	public static final int ID = JProtocol.UDP_ID;

	public static final int LENGTH = 8;

	/**
	 * Field objects for JFormatter
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public final static JField[] X_FIELDS = {
	    new JField("source", "src", new JStaticField<Udp, Integer>(0, 16) {

		    public Integer value(Udp header) {
			    return header.source();
		    }
	    }),

	    new JField("destination", "dst", new JStaticField<Udp, Integer>(2, 16) {

		    public Integer value(Udp header) {
			    return header.destination();
		    }
	    }),

	    new JField("length", "len", new JStaticField<Udp, Integer>(4, 32) {

		    public Integer value(Udp header) {
			    return header.length();
		    }
	    }),

	    new JField("checksum", "crc", new JStaticField<Udp, Integer>(6, 16) {

		    public Integer value(Udp header) {
			    return header.checksum();
		    }
	    }),

	};

	/**
	 * @param id
	 */
	public Udp() {
		super(ID, X_FIELDS, "udp");
		order(BYTE_ORDER);
	}

	public int source() {
		return getUShort(0);
	}

	public int destination() {
		return getUShort(2);
	}

	public int length() {
		return getUShort(4);
	}

	public int checksum() {
		return getUShort(6);
	}

}
