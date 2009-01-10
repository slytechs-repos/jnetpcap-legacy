/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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

import java.util.LinkedList;
import java.util.List;

import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.header.Ethernet;
import org.jnetpcap.packet.header.Ip4;
import org.jnetpcap.packet.header.Tcp;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class JFlow {

	private final JFlowKey key;

	private final boolean reversable;

	private final List<JPacket> all;

	private final List<JPacket> forward;

	private final List<JPacket> reverse;

	/**
	 * @param key
	 */
	public JFlow(JFlowKey key) {
		this.key = key;
		this.reversable = (key.getFlags() & JFlowKey.FLAG_REVERSABLE) > 0;

		if (this.reversable) {
			this.all = new LinkedList<JPacket>();
			this.forward = new LinkedList<JPacket>();
			this.reverse = new LinkedList<JPacket>();
		} else {
			this.all = new LinkedList<JPacket>();
			this.forward = null;
			this.reverse = null;
		}
	}

	/**
	 * @return the key
	 */
	public final JFlowKey getKey() {
		return this.key;
	}

	public boolean add(JPacket packet) {
		int dir = key.match(packet.getState().getFlowKey());
		if (dir == 0) {
			return false;
		}

		if (this.isReversable() == false) {
			return this.all.add(packet);
		}

		return ((dir == 1) ? forward.add(packet) : reverse.add(packet))
		    && all.add(packet);
	}

	/**
	 * @return the reversable
	 */
	public final boolean isReversable() {
		return this.reversable;
	}

	/**
	 * @return the all
	 */
	public final List<JPacket> getAll() {
		return this.all;
	}
	
	public int size() {
		return all.size();
	}

	/**
	 * @return the forward
	 */
	public final List<JPacket> getForward() {
		return (this.reversable) ? this.forward : this.all;
	}

	/**
	 * @return the reverse
	 */
	public final List<JPacket> getReverse() {
		return (this.reversable) ? this.reverse : null;
	}

	private Tcp tcp = new Tcp();

	private Ip4 ip = new Ip4();

	private Ethernet eth = new Ethernet();

	public String toString() {
		if (all.isEmpty()) {
			return key.toDebugString() + " size=" + all.size();
		}

		JPacket packet = all.get(0);
		if (packet.hasHeader(tcp) && packet.hasHeader(ip)) {
			String dst = FormatUtils.ip(ip.destination());
			String src = FormatUtils.ip(ip.source());
			String sport = "" + tcp.source();
			String dport = "" + tcp.destination();
			// String hash = Integer.toHexString(key.hashCode());

			return src + ":" + sport + " -> " + dst + ":" + dport
			    + " Tcp fw/rev/tot pkts=[" + forward.size() + "/" + reverse.size()
			    + "/" + all.size() + "]";

		} else if (packet.hasHeader(ip)) {
			String dst = FormatUtils.ip(ip.destination());
			String src = FormatUtils.ip(ip.source());
			String type = "" + ip.type();

			return src + " -> " + dst + ":" + type + " Ip4 tot pkts=[" + all.size()
			    + "]";

		} else if (packet.hasHeader(eth)) {
			String dst = FormatUtils.mac(eth.destination());
			String src = FormatUtils.mac(eth.source());
			String type = Integer.toHexString(eth.type());

			return src + " -> " + dst + ":" + type + " Eth tot pkts=[" + all.size()
			    + "]";

		} else {
			return key.toDebugString() + " packets=" + all.size();
		}
	}
}
