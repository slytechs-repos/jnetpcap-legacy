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

import java.io.IOException;

/**
 * A Pcap utility class which provides certain additional and convenience
 * methods.
 * 
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class PcapUtils {
	private PcapUtils() {
		// So no one can instatiate
	}

	/**
	 * Runs the dispatch function in a background thread. The function returns
	 * immediately and returns a PcapTask from which the user can interact with
	 * the background task.
	 * 
	 * @param pcap
	 *          an open pcap object
	 * @param cnt
	 *          number of packets to capture and exit, 0 for infinate
	 * @param handler
	 *          user supplied callback handler
	 * @param data
	 *          opaque, user supplied data object dispatched back to the handler
	 * @return a task object which allows interaction with the underlying capture
	 *         loop and thread
	 */
	public static PcapTask dispatchInBackground(final Pcap pcap, int cnt,
	    final PcapHandler handler, final Object data) {

		return new PcapTask(pcap, cnt, handler, data) {

			/**
			 * For dispatch type loop, we can interrupt the thread to breakout of the
			 * Pcap.dispatch() loop which is much quicker that calling
			 * Pcap.breakLoop().
			 */
//			@Override
//			protected void breakLoop() {
//				super.thread.interrupt();
//			}

			public void run() {
				int remaining = count;

				while (count == -1 || remaining > 0) {

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

					this.result = this.pcap.dispatch(count, this.handler, data);

					/*
					 * Check for errors
					 */
					if (result < 0) {
						throw new RuntimeException(pcap.getErr());
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
	 * Runs the loop function in a background thread. The function returns
	 * immediately and returns a PcapTask from which the user can interact with
	 * the background task.
	 * 
	 * @param pcap
	 *          an open pcap object
	 * @param cnt
	 *          number of packets to capture and exit, 0 for infinate
	 * @param handler
	 *          user supplied callback handler
	 * @param data
	 *          opaque, user supplied data object dispatched back to the handler
	 * @return a task object which allows interaction with the underlying capture
	 *         loop and thread
	 */
	public static PcapTask loopInBackground(Pcap pcap, int cnt,
	    PcapHandler handler, final Object data) {
		return new PcapTask(pcap, cnt, handler, data) {

			public void run() {
				this.result = this.pcap.loop(count, this.handler, data);
			}

		};

	}
}
