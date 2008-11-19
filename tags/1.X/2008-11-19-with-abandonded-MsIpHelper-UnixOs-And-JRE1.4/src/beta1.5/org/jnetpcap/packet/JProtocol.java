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

import org.jnetpcap.packet.header.Ethernet;
import org.jnetpcap.packet.header.IEEE802dot1q;
import org.jnetpcap.packet.header.IEEE802dot2;
import org.jnetpcap.packet.header.IEEE802dot3;
import org.jnetpcap.packet.header.IEEESnap;
import org.jnetpcap.packet.header.Icmp;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.packet.header.Ip6;
import org.jnetpcap.packet.header.L2TP;
import org.jnetpcap.packet.header.PPP;
import org.jnetpcap.packet.header.Payload;
import org.jnetpcap.packet.header.Tcp;
import org.jnetpcap.packet.header.Udp;

/**
 * Enum table of core protocols supported by the scanner.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public enum JProtocol {
	/**
	 * 
	 */
	PAYLOAD(Payload.class),
	ETHERNET(Ethernet.class),
	IP4(Ip4.class),
	IP6(Ip6.class),
	TCP(Tcp.class),
	UDP(Udp.class),
	IEEE_802DOT3(IEEE802dot3.class),
	IEEE_802DOT2(IEEE802dot2.class),
	IEEE_SNAP(IEEESnap.class),
	IEEE_802DOT1Q(IEEE802dot1q.class),
	L2TP(L2TP.class),
	PPP(PPP.class),
	ICMP(Icmp.class), ;

	/**
	 * Unique ID of this protocol
	 */
	public final int ID;

	/**
	 * Main class for the network header of this protocol
	 */
	public final Class<? extends JHeader> clazz;

	/**
	 * A header scanner that capable of scanning this protocol. All protocols
	 * defined in JProtocol are bound to a direct native scanner. While it is
	 * possible to override this default using JRegistery with a custom scanner.
	 */
	public final JHeaderScanner scan;

	public final static int PAYLOAD_ID = 0;

	public final static int ETHERNET_ID = 1;

	public final static int IP4_ID = 2;

	public final static int IP6_ID = 3;

	public final static int TCP_ID = 4;

	public final static int UDP_ID = 5;

	public final static int IEEE_802DOT3_ID = 6;

	public final static int IEEE_802DOT2_ID = 7;

	public final static int IEEE_SNAP_ID = 8;

	public final static int IEEE_802DOT1Q_ID = 9;

	public final static int L2TP_ID = 10;

	public final static int PPP_ID = 11;

	public final static int ICMP_ID = 12;

	private JProtocol(Class<? extends JHeader> c) {
		this.clazz = c;
		this.ID = ordinal();

		try {
			this.scan = new JHeaderScanner(this);
		} catch (UnregisteredScannerException e) {
			e.printStackTrace(System.err);
			throw new IllegalStateException(e);
		}
	}

	public static boolean isCoreProtocol(int id) {
		return id < values().length;
	}

	public static boolean isCoreProtocol(Class<? extends JHeader> c) {
		return (valueOf(c) == null) ? false : true;
	}

	public static JProtocol valueOf(Class<? extends JHeader> c) {
		for (JProtocol p : values()) {
			if (p.clazz == c) {
				return p;
			}
		}

		return null;
	}

	public static JProtocol valueOf(int id) {
		if (id >= values().length) {
			return null;
		}

		return values()[id];
	}
}