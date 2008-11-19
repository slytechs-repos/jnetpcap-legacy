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
import java.util.List;

import org.jnetpcap.ms.MSIpAdapterIndexMap;
import org.jnetpcap.ms.MSIpHelper;
import org.jnetpcap.ms.MSIpInterfaceInfo;
import org.jnetpcap.ms.MSMibIfRow;
import org.jnetpcap.nio.JNumber;
import org.jnetpcap.unix.UnixOs;
import org.jnetpcap.unix.UnixOs.IfReq;

/**
 * A Pcap utility class which provides certain additional and convenience
 * methods.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public final class PcapUtils {
	/**
	 * Make sure that we are thread safe and don't clober each others messages
	 */
	private final static ThreadLocal<StringBuffer> buf =
	    new ThreadLocal<StringBuffer>() {

		    @Override
		    protected StringBuffer initialValue() {
			    return new StringBuffer();
		    }

	    };

	/**
	 * Temp buffer for handling ip6 address compression
	 */
	private final static byte[] ip6_buf = new byte[16];

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
	public static <T> PcapTask<T> dispatchInBackground(Pcap pcap, int cnt,
	    PcapHandler<T> handler, final T data) {

		return new PcapTask<T>(pcap, cnt, handler, data) {

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

					this.result = this.pcap.dispatch(count, this.handler, data);

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
	 * Returns a common shared StringBuffer buffer
	 * 
	 * @return a buffer
	 */
	public static StringBuffer getBuf() {
		return buf.get();
	}

	/**
	 * Retrieves a network hardware address or MAC for a network interface
	 * 
	 * @see Pcap#findAllDevs(List, Appendable)
	 * @param netif
	 *          network device as retrieved from Pcap.findAllDevs().
	 * @return network interface hardware address or null if unable to retrieve it
	 * @throws IOException
	 *           any communication errors
	 */
	public static byte[] getHardwareAddress(PcapIf netif) throws IOException {
		return getHardwareAddress(netif.getName());
	}

	/**
	 * Retrieves a network hardware address or MAC for a network interface
	 * 
	 * @param device
	 *          network interface name
	 * @return network interface hardware address or null if unable to retrieve it
	 * @throws IOException
	 *           any communication errors
	 */
	public native static byte[] getHardwareAddress(String device) throws IOException;

	/**
	 * Retrieve from using Microsoft API
	 * 
	 * @param device
	 * @return
	 * @throws IOException
	 */
	private static byte[] getMSHardwareAddress(String device) throws IOException {
		if (!MSIpHelper.isSupported()) {
			return null;
		}

		@SuppressWarnings("unused")
		int r = 0;
		JNumber size = new JNumber();
		if ((r = MSIpHelper.getInterfaceInfo(null, size)) != MSIpHelper.ERROR_INSUFFICIENT_BUFFER) {
			throw new IOException("MSIpHelper.getInterfaceInfo() failed");
		}

		MSIpInterfaceInfo info = new MSIpInterfaceInfo(size.intValue());
		if ((r = MSIpHelper.getInterfaceInfo(info, size)) != MSIpHelper.NO_ERROR) {
			throw new IOException("MSIpHelper.getInterfaceInfo() failed");
		}

		for (int i = 0; i < info.numAdapters(); i++) {
			MSIpAdapterIndexMap adapter = info.adapter(i);

			if (device.toUpperCase().equals(adapter.name().toUpperCase())) {
				MSMibIfRow row = new MSMibIfRow();
				row.dwIndex(adapter.index());
				if ((r = MSIpHelper.getIfEntry(row)) != MSIpHelper.NO_ERROR) {
					throw new IOException("MSIpHelper.getIfEntry() failed");
				}

				return row.bPhysAddr();
			}
		}
		return null;
	}

	/**
	 * Retrieve using Linux/AIX/HPUP API
	 * 
	 * @param device
	 * @return
	 * @throws IOException
	 */
	private static byte[] getUnixHardwareAddress(String device)
	    throws IOException {
		if (!UnixOs.isSupported() || !UnixOs.isSupported(UnixOs.SOCK_PACKET)
		    || !UnixOs.isSupported(UnixOs.SIOCGIFHWADDR)) {
			return null;
		}

		int d =
		    UnixOs.socket(UnixOs.PF_INET, UnixOs.SOCK_DGRAM,
		        UnixOs.PROTOCOL_DEFAULT);
		if (d == -1) {
			throw new IOException(UnixOs.strerror(UnixOs.errno()));
		}

		IfReq ir = new IfReq();

		ir.ifr_name(device);

		int r = UnixOs.ioctl(d, UnixOs.SIOCGIFHWADDR, ir);
		UnixOs.close(d);
		if (r == -1) {
			return null;
		}

		byte[] ha = ir.ifr_hwaddr();
		return ha;
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
	public static <T> PcapTask<T> loopInBackground(Pcap pcap, int cnt,
	    PcapHandler<T> handler, final T data) {
		return new PcapTask<T>(pcap, cnt, handler, data) {

			public void run() {
				this.result = pcap.loop(count, handler, data);
			}

		};

	}

	/**
	 * Copies the contents of the source buf to appendable
	 * 
	 * @param buf
	 *          source
	 * @param appendable
	 *          destination
	 * @throws IOException
	 *           any IO errors produced by the appendable
	 */
	public static void toAppendable(StringBuffer buf, Appendable appendable)
	    throws IOException {

		if (buf.length() != 0) {
			appendable.append(buf);
		}
	}

	/**
	 * Copies the contents of the source buf to builder
	 * 
	 * @param buf
	 *          source
	 * @param builder
	 *          destination
	 */
	public static void toStringBuilder(StringBuffer buf, StringBuilder builder) {
		builder.setLength(0);

		if (buf.length() != 0) {
			builder.append(buf);
		}
	}

	private PcapUtils() {
		// So no one can instatiate
	}

}
