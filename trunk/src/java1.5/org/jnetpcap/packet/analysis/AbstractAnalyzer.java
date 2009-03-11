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
package org.jnetpcap.packet.analysis;

import java.util.Queue;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.tcpip.TcpInvalidStreamHashcode;
import org.jnetpcap.util.TimeoutQueue;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AbstractAnalyzer implements JAnalyzer {

	/**
	 * Priority within the sorted set. It has to be final as its used in the
	 * sorting algorithm. Can't change it at runtime after analyzer has been
	 * already added to the set.
	 */
	private final int priority;

	private JAnalyzer parent;

	/**
	 * @param priority
	 * @param parent
	 */
	public AbstractAnalyzer() {
		this.priority = -1;
		this.parent = null;
	}

	/**
	 * @param priority
	 * @param parent
	 */
	public AbstractAnalyzer(int priority) {
		this.priority = priority;
		this.parent = null;
	}

	/**
	 * @param priority
	 * @param parent
	 */
	public AbstractAnalyzer(int priority, JAnalyzer parent) {
		this.priority = priority;
		this.parent = parent;
	}

	public long getProcessingTime() {
		return (parent == null) ? null : parent.getProcessingTime();
	}

	/**
	 * @param packet
	 * @throws TcpInvalidStreamHashcode
	 */
	public abstract boolean processPacket(JPacket packet)
	    throws AnalysisException;

	public int getPriority() {
		return (priority == -1 && parent != null) ? parent.getPriority()
		    : this.priority;
	}

	public void setParent(JAnalyzer parent) {
		this.parent = parent;
	}

	public Queue<JPacket> getInQueue() {
		return (parent == null) ? null : parent.getInQueue();
	}

	public Queue<JPacket> getOutQueue() {
		return (parent == null) ? null : parent.getOutQueue();
	}

	public TimeoutQueue getTimeoutQueue() {
		return (parent == null) ? null : parent.getTimeoutQueue();
	}

	public int hold() {
		return (parent == null) ? -1 : parent.hold();
	}

	public int release() {
		return (parent == null) ? -1 : parent.release();
	}

	public boolean processHeaders(JPacket packet) {
		return (parent == null) ? true : parent.processHeaders(packet);
	}

	public boolean processHeaders(JPacket packet, long map) {
		return (parent == null) ? true : parent.processHeaders(packet, map);
	}

	public void consumePacket(JPacket packet) {
		if (parent != null) {
			parent.consumePacket(packet);
		}
	}
}
