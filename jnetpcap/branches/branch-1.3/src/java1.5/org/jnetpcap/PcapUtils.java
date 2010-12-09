/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.jnetpcap;

import java.io.IOException;
import java.util.List;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

// TODO: Auto-generated Javadoc
/**
 * The Class PcapUtils.
 */
public final class PcapUtils {
	
	/**
	 * Dispatch in background.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param pcap
	 *          the pcap
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param data
	 *          the data
	 * @return the pcap task
	 */
	public static <T> PcapTask<T> dispatchInBackground(
	    Pcap pcap,
	    int cnt,
	    final ByteBufferHandler<T> handler,
	    final T data) {

		return new PcapTask<T>(pcap, cnt, data) {

			public void run() {
				int remaining = count;

				while (remaining > 0) {

					/*
					 * Yield to other threads on every iteration of the loop, another
					 * words everytime the libpcap buffer has been completely filled.
					 * Except on the first loop, we don't want to yield but go right into
					 * the dispatch loop. Also having the yield at the top allows the
					 * thread to exit when total count packets have been dispatched and
					 * thus avoid an extra explicit yied, but achive implicit yield
					 * because this thread will terminate.
					 */
					if (remaining != 0) {
						Thread.yield();
					}

					this.result = this.pcap.dispatch(count, handler, data);

					/*
					 * Check for errors
					 */
					if (result < 0) {
						break;
					}

					/*
					 * If not an error, result contains number of packets dispatched or
					 * how many packets fit into the libpcap buffer
					 */
					remaining -= result;
				}
			}
		};
	}

	/**
	 * Dispatch in background.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param pcap
	 *          the pcap
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param data
	 *          the data
	 * @return the pcap task
	 */
	public static <T> PcapTask<T> dispatchInBackground(
	    Pcap pcap,
	    int cnt,
	    final JBufferHandler<T> handler,
	    final T data) {

		return new PcapTask<T>(pcap, cnt, data) {

			public void run() {
				int remaining = count;

				while (remaining > 0) {

					/*
					 * Yield to other threads on every iteration of the loop, another
					 * words everytime the libpcap buffer has been completely filled.
					 * Except on the first loop, we don't want to yield but go right into
					 * the dispatch loop. Also having the yield at the top allows the
					 * thread to exit when total count packets have been dispatched and
					 * thus avoid an extra explicit yied, but achive implicit yield
					 * because this thread will terminate.
					 */
					if (remaining != 0) {
						Thread.yield();
					}

					this.result = this.pcap.dispatch(count, handler, data);

					/*
					 * Check for errors
					 */
					if (result < 0) {
						break;
					}

					/*
					 * If not an error, result contains number of packets dispatched or
					 * how many packets fit into the libpcap buffer
					 */
					remaining -= result;
				}
			}
		};
	}

	/**
	 * Gets the hardware address.
	 * 
	 * @param netif
	 *          the netif
	 * @return the hardware address
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static byte[] getHardwareAddress(PcapIf netif) throws IOException {
		return getHardwareAddress(netif.getName());
	}

	/**
	 * Gets the hardware address.
	 * 
	 * @param device
	 *          the device
	 * @return the hardware address
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public native static byte[] getHardwareAddress(String device)
	    throws IOException;

	/**
	 * Loop in background.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param pcap
	 *          the pcap
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param data
	 *          the data
	 * @return the pcap task
	 */
	public static <T> PcapTask<T> loopInBackground(
	    Pcap pcap,
	    int cnt,
	    final ByteBufferHandler<T> handler,
	    final T data) {
		return new PcapTask<T>(pcap, cnt, data) {

			public void run() {
				this.result = pcap.loop(count, handler, data);
			}

		};
	}

	/**
	 * Loop in background.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param pcap
	 *          the pcap
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param data
	 *          the data
	 * @return the pcap task
	 */
	public static <T> PcapTask<T> loopInBackground(
	    Pcap pcap,
	    int cnt,
	    final JBufferHandler<T> handler,
	    final T data) {
		return new PcapTask<T>(pcap, cnt, data) {

			public void run() {
				this.result = pcap.loop(count, handler, data);
			}

		};
	}

	/**
	 * Inject loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param id
	 *          the id
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param packet
	 *          the packet
	 * @return the int
	 */
	public static <T> int injectLoop(
	    int cnt,
	    int id,
	    PcapPacketHandler<T> handler,
	    T user,
	    PcapPacket packet) {

		return injectLoop(cnt, id, handler, user, packet, packet.getState(), packet
		    .getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Inject loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param id
	 *          the id
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param packet
	 *          the packet
	 * @param state
	 *          the state
	 * @param header
	 *          the header
	 * @param scanner
	 *          the scanner
	 * @return the int
	 */
	private native static <T> int injectLoop(
	    int cnt,
	    int id,
	    PcapPacketHandler<T> handler,
	    T user,
	    PcapPacket packet,
	    JPacket.State state,
	    PcapHeader header,
	    JScanner scanner);

	/**
	 * Instantiates a new pcap utils.
	 */
	private PcapUtils() {
		// So no one can instatiate
	}

}
