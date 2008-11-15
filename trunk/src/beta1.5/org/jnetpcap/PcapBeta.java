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

import org.jnetpcap.nio.JNumber;
import org.jnetpcap.packet.JScanner;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class PcapBeta
    extends Pcap {

	/**
	 * 
	 */
	private PcapBeta() {
		// Empty
	}

	public native <T> int dispatch(int cnt, JBufferHandler<T> handler, T user);

	public <T> int dispatch(int cnt, JPacketHandler<T> handler, T user) {
		return dispatch(cnt, handler, user, JScanner.getThreadLocal());
	}

	public native <T> int dispatch(int cnt, JPacketHandler<T> handler, T user,
	    JScanner scanner);

	/**
	 * <p>
	 * Runs the dispatch function in a background thread. The method returns
	 * immediately and returns a PcapTask from which the user can interact with
	 * the background task.
	 * </p>
	 * <p>
	 * Note that this method is not part of the native libpcap API specification.
	 * </p>
	 * 
	 * @since 1.2
	 * @param cnt
	 *          number of packets to capture and exit, 0 for infinate
	 * @param handler
	 *          user supplied callback handler
	 * @param data
	 *          opaque, user supplied data object dispatched back to the handler
	 * @return a task object which allows interaction with the underlying capture
	 *         loop and thread
	 */
	public <T> PcapTask<T> dispatchInBackground(int cnt, PcapHandler<T> handler,
	    final T data) {
		return PcapUtils.dispatchInBackground(this, cnt, handler, data);
	}

	public native <T> int loop(int cnt, JBufferHandler<T> handler, T user);

	public <T> int loop(int cnt, JPacketHandler<T> handler, T user) {
		return loop(cnt, handler, user, JScanner.getThreadLocal());
	}

	public native <T> int loop(int cnt, JPacketHandler<T> handler, T user,
	    JScanner scanner);

	/**
	 * <p>
	 * Runs the loop function in a background thread. The method returns
	 * immediately and returns a PcapTask from which the user can interact with
	 * the background task.
	 * </p>
	 * <p>
	 * Note that this method is not part of the native libpcap API specification.
	 * </p>
	 * 
	 * @since 1.2
	 * @param cnt
	 *          number of packets to capture and exit, 0 for infinate
	 * @param handler
	 *          user supplied callback handler
	 * @param data
	 *          opaque, user supplied data object dispatched back to the handler
	 * @return a task object which allows interaction with the underlying capture
	 *         loop and thread
	 */
	public <T> PcapTask<T> loopInBackground(int cnt, PcapHandler<T> handler,
	    final T data) {
		return PcapUtils.loopInBackground(this, cnt, handler, data);
	}

	/**
	 * Determines the network number and mask associated with the network device.
	 * Both netp and maskp are integer object references whos value is set from
	 * within the call. This is the way that pcap natively passes back these two
	 * values.
	 * <p>
	 * <b>Note:</b> this method is deprecated in pcap as it can not be used to
	 * pass back information about IP v6 addresses.
	 * </p>
	 * 
	 * @param device
	 *          device to do the lookup on
	 * @param netp
	 *          object which will contain the value of network address
	 * @param maskp
	 *          object which will contain the value of network netmask
	 * @param errbuf
	 *          any error messages if return value is -1
	 * @return 0 on success otherwise -1 on error
	 * @since 1.2
	 */
	public native static int lookupNet(String device, JNumber netp,
	    JNumber maskp, StringBuffer errbuf);

	/**
	 * Determines the network number and mask associated with the network device.
	 * Both netp and maskp are integer object references whos value is set from
	 * within the call. This is the way that pcap natively passes back these two
	 * values.
	 * <p>
	 * <b>Note:</b> this method is deprecated in pcap as it can not be used to
	 * pass back information about IP v6 addresses.
	 * </p>
	 * 
	 * @param device
	 *          device to do the lookup on
	 * @param netp
	 *          object which will contain the value of network address
	 * @param maskp
	 *          object which will contain the value of network netmask
	 * @param errbuf
	 *          any error messages if return value is -1
	 * @return 0 on success otherwise -1 on error
	 */
	public static int lookupNet(String device, JNumber netp, JNumber maskp,
	    StringBuilder errbuf) {
		final int r = lookupNet(device, netp, maskp, PcapUtils.getBuf());

		PcapUtils.toStringBuilder(PcapUtils.getBuf(), errbuf);

		return r;
	}

	/**
	 * Determines the network number and mask associated with the network device.
	 * Both netp and maskp are integer object references whos value is set from
	 * within the call. This is the way that pcap natively passes back these two
	 * values.
	 * <p>
	 * <b>Note:</b> this method is deprecated in libpcap as it can not be used to
	 * pass back information about IP v6 addresses.
	 * </p>
	 * 
	 * @param device
	 *          device to do the lookup on
	 * @param netp
	 *          object which will contain the value of network address
	 * @param maskp
	 *          object which will contain the value of network netmask
	 * @param errbuf
	 *          any error messages if return value is -1
	 * @return 0 on success otherwise -1 on error
	 * @since 1.2
	 */
	public static int lookupNet(String device, JNumber netp, JNumber maskp,
	    Appendable errbuf) throws IOException {
		final int r = lookupNet(device, netp, maskp, PcapUtils.getBuf());

		PcapUtils.toAppendable(PcapUtils.getBuf(), errbuf);

		return r;
	}

}
