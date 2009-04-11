/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.winpcap;

/**
 * Class allows extra statistics to be reported by WinPcap.statsEx();
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapStatEx {
	
	private static native void initIDs();
	
	static {
		initIDs();
	}

	private long rxPackets;

	private long txPackets;

	private long rxBytes;

	private long txBytes;

	private long rxErrors;

	private long txErrors;

	private long rxDropped;

	private long txDropped;

	private long multicast;

	private long collisions;

	/* detailed rx_errors: */
	private long rxLengthErrors;

	private long rxOverErrors;

	private long rxCrcErrors;

	private long rxFrameErrors;

	private long rxFifoErrors;

	private long rxMissedErrors;

	/* detailed tx_errors */
	private long txAbortedErrors;

	private long txCarrierErrors;

	private long txFifoErrors;

	private long txHeartbeatErrors;

	private long txWindowErrors;

	/**
	 * total packets received
	 * 
	 * @return the rxPackets
	 */
	public final long getRxPackets() {
		return this.rxPackets;
	}

	/**
	 * total packets transmitted
	 * 
	 * @return the txPackets
	 */
	public final long getTxPackets() {
		return this.txPackets;
	}

	/**
	 * total bytes received
	 * 
	 * @return the rxBytes
	 */
	public final long getRxBytes() {
		return this.rxBytes;
	}

	/**
	 * total bytes transmitted
	 * 
	 * @return the txBytes
	 */
	public final long getTxBytes() {
		return this.txBytes;
	}

	/**
	 * bad packets received
	 * 
	 * @return the rxErrors
	 */
	public final long getRxErrors() {
		return this.rxErrors;
	}

	/**
	 * packet transmit problems
	 * 
	 * @return the txErrors
	 */
	public final long getTxErrors() {
		return this.txErrors;
	}

	/**
	 * no space in Rx buffers
	 * 
	 * @return the rxDropped
	 */
	public final long getRxDropped() {
		return this.rxDropped;
	}

	/**
	 * no space available for Tx
	 * 
	 * @return the txDropped
	 */
	public final long getTxDropped() {
		return this.txDropped;
	}

	/**
	 * multicast packets received
	 * 
	 * @return the multicast
	 */
	public final long getMulticast() {
		return this.multicast;
	}

	/**
	 * @return the collisions
	 */
	public final long getCollisions() {
		return this.collisions;
	}

	/**
	 * @return the rxLengthErrors
	 */
	public final long getRxLengthErrors() {
		return this.rxLengthErrors;
	}

	/**
	 * receiver ring buff overflow
	 * 
	 * @return the rxOverErrors
	 */
	public final long getRxOverErrors() {
		return this.rxOverErrors;
	}

	/**
	 * recv'd pkt with crc error
	 * 
	 * @return the rxCrcErrors
	 */
	public final long getRxCrcErrors() {
		return this.rxCrcErrors;
	}

	/**
	 * recv'd frame alignment error
	 * 
	 * @return the rxFrameErrors
	 */
	public final long getRxFrameErrors() {
		return this.rxFrameErrors;
	}

	/**
	 * recv'r fifo overrun
	 * 
	 * @return the rxFifoErrors
	 */
	public final long getRxFifoErrors() {
		return this.rxFifoErrors;
	}

	/**
	 * recv'r missed packet
	 * 
	 * @return the rxMissedErrors
	 */
	public final long getRxMissedErrors() {
		return this.rxMissedErrors;
	}

	/**
	 * @return the txAbortedErrors
	 */
	public final long getTxAbortedErrors() {
		return this.txAbortedErrors;
	}

	/**
	 * @return the txCarrierErrors
	 */
	public final long getTxCarrierErrors() {
		return this.txCarrierErrors;
	}

	/**
	 * @return the txFifoErrors
	 */
	public final long getTxFifoErrors() {
		return this.txFifoErrors;
	}

	/**
	 * @return the txHeartbeatErrors
	 */
	public final long getTxHeartbeatErrors() {
		return this.txHeartbeatErrors;
	}

	/**
	 * @return the txWindowErrors
	 */
	public final long getTxWindowErrors() {
		return this.txWindowErrors;
	}
}
