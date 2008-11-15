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
import java.util.ArrayList;
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
	 * @param bs
	 * @return
	 */
	@SuppressWarnings("unused")
	public static String asString(byte[] bs) {
		return asString(bs, ':');
	}

	/**
	 * @param a
	 * @param separator
	 * @return
	 */
	public static String asString(byte[] a, char separator) {
		StringBuilder buf = new StringBuilder();
		for (byte b : a) {
			if (buf.length() != 0) {
				buf.append(separator);
			}

			if (b >= 0 && b < 16) {
				buf.append('0');
			}

			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		}

		return buf.toString();
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
	public static byte[] getHardwareAddress(String device) throws IOException {

		/*
		 * Translate device name on MS systems from NPF to TCPIP namespace
		 */
		byte[] mac =
		    getMSHardwareAddress(device.toUpperCase().replaceAll("NPF_", "TCPIP_"));
		if (mac != null) {
			return mac;
		}

		mac = getUnixHardwareAddress(device);
		if (mac != null) {
			return mac;
		}

		return null;
	}

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

	/**
	 * @param a
	 * @param separator
	 * @param radix
	 * @return
	 */
	public static String asString(byte[] a, char separator, int radix) {
		StringBuilder buf = new StringBuilder();
		for (byte b : a) {
			if (buf.length() != 0) {
				buf.append(separator);
			}
			if (radix == 16) {
				buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
			} else {
				buf.append(Integer.toString((b < 0) ? b + 256 : b).toUpperCase());

			}
		}

		return buf.toString();
	}

	/**
	 * Temp buffer for handling ip6 address compression
	 */
	private final static byte[] ip6_buf = new byte[16];

	private static final String SPACE_CHAR = " ";

	private static final String NEWLINE_CHAR = "\n";

	/**
	 * Handles various forms of ip6 addressing
	 * 
	 * <pre>
	 *  2001:0db8:0000:0000:0000:0000:1428:57ab
	 * 	2001:0db8:0000:0000:0000::1428:57ab
	 * 	2001:0db8:0:0:0:0:1428:57ab
	 * 	2001:0db8:0:0::1428:57ab
	 * 	2001:0db8::1428:57ab
	 * 	2001:db8::1428:57ab
	 * </pre>
	 * 
	 * @param value
	 * @param c
	 * @return
	 */
	public static String asStringIp6(byte[] a, boolean holes) {
		StringBuilder buf = new StringBuilder();

		int len = 0;
		int start = -1;
		/*
		 * Check for byte compression where sequential zeros are replaced with ::
		 */
		for (int i = 0; i < a.length && holes; i++) {
			if (a[i] == 0) {
				if (len == 0) {
					start = i;
				}

				len++;
			}

			/*
			 * Only the first sequence of 0s is compressed, so break out
			 */
			if (a[i] != 0 && len != 0) {
				break;
			}
		}

		/*
		 * Now round off to even length so that only pairs are compressed
		 */
		if (start != -1 && (start % 2) == 1) {
			start++;
			len--;
		}

		if (start != -1 && (len % 2) == 1) {
			len--;
		}

		for (int i = 0; i < a.length; i++) {
			if (i == start) {
				buf.append(':');
				i += len - 1;

				if (i == a.length - 1) {
					buf.append(':');
				}
				continue;
			}

			byte b = a[i];

			if (buf.length() != 0 && (i % 2) == 0) {
				buf.append(':');
			}
			if (b < 16) {
				buf.append('0');
			}
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		}

		return buf.toString();
	}

	private final static List<String> multiLineStringList =
	    new ArrayList<String>();

	/**
	 * @param a
	 * @param prefix
	 * @param indentFirstLine
	 * @param addressOffset
	 * @param dataOffset
	 * @return
	 */
	public static String[] hexdump(byte[] a, int addressOffset, int dataOffset,
	    boolean doAddress, boolean doText, boolean doData) {

		multiLineStringList.clear();

		for (int i = 0; i + dataOffset < a.length; i += 16) {
			multiLineStringList.add(hexLine(a, i + addressOffset, i + dataOffset,
			    doAddress, doText, doData));
		}

		return multiLineStringList.toArray(new String[multiLineStringList.size()]);
	}

	/**
	 * @param a
	 * @param address
	 * @param i
	 * @param doAddress
	 * @param doText
	 * @return
	 */
	public static String hexLine(byte[] a, int address, int i, boolean doAddress,
	    boolean doText, boolean doData) {
		String s = "";
		if (doAddress) {
			s += hexLineAddress(address);
			s += ":" + SPACE_CHAR;
		}

		if (doData) {
			s += hexLineData(a, i);
		}

		if (doText) {
			s += SPACE_CHAR;
			s += SPACE_CHAR;
			s += SPACE_CHAR;

			s += hexLineText(a, i);
		}

		return (s);
	}

	public static String hexLineText(byte[] data, int offset) {

		String s = "";

		int i;
		for (i = 0; i + offset < data.length && i < 16; i++) {
			s += table[data[i + offset] & 0xFF];

			// if(Character.isLetterOrDigit(table[data[i + offset] & 0xFF]) ||
			// (table[data[i + offset] & 0xFF]) == ' ')
			// s += " " + table[data[i + offset] & 0xFF];
			// else
			// s += " " + NONPRINTABLE_CHAR;
		}

		/**
		 * Continue the loop and fill in any missing data less than 16 bytes.
		 */
		for (; i < 16; i++) {
			s += SPACE_CHAR;
		}

		return (s);
	}

	static String[] table = new String[256];
	static {

		for (int i = 0; i < 31; i++) {
			table[i] = "\\" + Integer.toHexString(i);
			if (table[i].length() == 2)
				table[i] += " ";
		}

		for (int i = 31; i < 127; i++)
			table[i] = new String(new byte[] {
			    (byte) i,
			    ' ',
			    ' ' });

		for (int i = 127; i < 256; i++) {
			table[i] = "\\" + Integer.toHexString(i);
			if (table[i].length() == 2)
				table[i] += " ";
		}

		table[0] = "\\0 ";
		table[7] = "\\a ";
		table[11] = "\\v ";
		table['\b'] = "\\b ";
		table['\t'] = "\\t ";
		table['\n'] = "\\n ";
		table['\f'] = "\\f ";
		table['\r'] = "\\r ";
	}

	public static String hexLineAddress(int address) {
		String s = "";

		s = Integer.toHexString(address);

		for (int i = s.length(); i < 4; i++)
			s = "0" + s;

		return (s);
	}

	public static String hexLineData(byte[] data, int offset) {
		String s = "";

		int i = 0;
		for (i = 0; i + offset < data.length && i < 16; i++) {

			/**
			 * Insert a space every 4 characaters.
			 */
			if (i % 4 == 0 && i != 0)
				s += SPACE_CHAR;

			s += toHexString(data[i + offset]);
		}

		/**
		 * Continue the loop and append spaces to fill in the missing data.
		 */
		for (; i < 16; i++) {
			/**
			 * Insert a space every 4 characaters.
			 */
			if (i % 4 == 0 && i != 0)
				s += SPACE_CHAR;

			s += SPACE_CHAR + SPACE_CHAR;
		}

		return (s);
	}

	public static String toHexString(byte b) {
		String s = Integer.toHexString(((int) b) & 0xFF);

		if (s.length() == 1)
			return ("0" + s);

		return (s);
	}

	/**
	 * @param pkt_data
	 * @return
	 */
	public static byte[] toByteArray(String pkt_data) {

		String s = pkt_data.replaceAll(" |\n", "");

		byte[] b = new byte[s.length() / 2];

		if ((s.length() % 2) != 0) {
			System.err.println(s);
			throw new IllegalArgumentException(
			    "need even number of hex double digits [" + s.length() + "]");
		}

		for (int i = 0; i < s.length(); i += 2) {
			String q = s.substring(i, i + 2);
//			System.out.print(q);
			b[i / 2] = (byte)Integer.parseInt(q, 16);
		}

		return b;
	}

}
