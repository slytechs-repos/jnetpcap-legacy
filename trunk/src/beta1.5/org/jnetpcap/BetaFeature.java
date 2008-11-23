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
package org.jnetpcap;

import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.JScanner;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class BetaFeature
    extends Pcap {

	/**
	 * 
	 */
	private BetaFeature() {
		// Empty
	}

	public static <T> int dispatch(Pcap pcap, int cnt, int id, JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(pcap, cnt, id, handler, user, packet, packet.getState(), packet.getCaptureHeader(),
		    JScanner.getThreadLocal());
	}

	private static native <T> int dispatch(Pcap pcap, int cnt, int id, JPacketHandler<T> handler, T user,
	    JPacket packet, JPacket.State state, PcapHeader header, JScanner scanner);

	public static <T> int loop(Pcap pcap, int cnt, JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(pcap, cnt, JProtocol.id(pcap), handler, user, packet, packet.getState(), packet.getCaptureHeader(), JScanner
		    .getThreadLocal());
	}

	public static <T> int loop(Pcap pcap, int cnt, int id, JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(pcap, cnt, id, handler, user, packet, packet.getState(), packet.getCaptureHeader(), JScanner
		    .getThreadLocal());
	}

	private static native <T> int loop(Pcap pcap, int cnt, int id, JPacketHandler<T> handler, T user,
	    JPacket packet, JPacket.State state, PcapHeader header, JScanner scanner);

}
