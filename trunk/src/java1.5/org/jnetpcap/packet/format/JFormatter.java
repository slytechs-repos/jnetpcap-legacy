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
package org.jnetpcap.packet.format;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Writer;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Comparator;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.Stack;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.UnregisteredHeaderException;
import org.jnetpcap.packet.structure.JField;

/**
 * Formats decoded contents of a JPacket for output.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JFormatter {

	public abstract static class AbstractResolver implements Resolver {

		private static class TimeoutEntry {
			public int key;

			public long timeout;

			/**
			 * @param key
			 */
			public TimeoutEntry(int key) {
				this.key = key;
				timeout = System.currentTimeMillis() + 30 * 1000; // 30 second timeout
			}
		}

		private final static Queue<TimeoutEntry> timeoutQueue =
		    new PriorityQueue<TimeoutEntry>(100, new Comparator<TimeoutEntry>() {

			    public int compare(TimeoutEntry o1, TimeoutEntry o2) {
				    return (int) (o1.timeout - o2.timeout);
			    }

		    });

		private final Map<Integer, String> cache = new HashMap<Integer, String>();

		protected void addToCache(byte[] address, String name, int hash) {
			cache.put(hash, name);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.format.JFormatter.Resolver#isResolved(byte[])
		 */
		public boolean canBeResolved(byte[] address) {
			return resolve(address) != null;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.format.JFormatter.Resolver#isCached(byte[])
		 */
		public boolean isCached(byte[] address) {
			return this.cache.containsKey(toHashCode(address));
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.format.JFormatter.Resolver#resolve(byte[])
		 */
		public final String resolve(byte[] address) {

			timeoutCache();

			int hash = toHashCode(address);
			String s = cache.get(hash);
			if (cache.containsKey(hash)) {
				return s;
			}

			s = resolveToName(address, hash);

			addToCache(address, s, hash);

			if (s == null) {
				timeoutQueue.add(new TimeoutEntry(hash));
			}

			return s;
		}

		/**
		 * @param address
		 * @param hash
		 */
		protected abstract String resolveToName(byte[] address, int hash);

		private void timeoutCache() {
			final long t = System.currentTimeMillis();

			for (Iterator<TimeoutEntry> i = timeoutQueue.iterator(); i.hasNext();) {
				TimeoutEntry e = i.next();
				if (e.timeout < t) {
					System.out.printf("timedout %s\n", cache.get(e.key));
					cache.remove(e.key);
					i.remove();
				} else {
					break;
				}
			}
		}

		protected abstract int toHashCode(byte[] address);
	}

	/**
	 * Detail level to include in formatted output
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Detail {
		/**
		 * Full detail using multi line output if neccessary
		 */
		MULTI_LINE_FULL_DETAIL,

		/**
		 * Summary of one major component per line
		 */
		MULTI_LINE_SUMMARY,

		/**
		 * Supress output
		 */
		NONE,

		/**
		 * Compress output to a single line of output for the entire component
		 */
		ONE_LINE_SUMMARY,
	}

	public static class IpResolver
	    extends AbstractResolver {

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.format.JFormatter.AbstractResolver#resolveToName(byte[],
		 *      int)
		 */
		@Override
		protected String resolveToName(byte[] address, int hash) {
			try {
				InetAddress i = InetAddress.getByAddress(address);
				String host = i.getHostName();
				if (Character.isDigit(host.charAt(0)) == false) {
					addToCache(address, host, hash);
					return host;
				}

			} catch (UnknownHostException e) {
				e.printStackTrace();
			}
			return null;

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.format.JFormatter.AbstractResolver#toHashCode(byte[])
		 */
		@Override
		protected int toHashCode(byte[] address) {
			int hash =
			    ((address[3] < 0) ? address[3] + 256 : address[3])
			        | ((address[2] < 0) ? address[2] + 256 : address[2]) << 8
			        | ((address[1] < 0) ? address[1] + 256 : address[1]) << 16
			        | ((address[0] < 0) ? address[0] + 256 : address[0]) << 24;

			return hash;
		}

	}

	/**
	 * Priority assigned to JFields. The priority of a field is used to determine
	 * which fields to include as part of format Detail.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Priority {

		/**
		 * High priority fields are included in every type of output
		 */
		HIGH,

		/**
		 * Low priority fields are only included in MULTI_LINE_FULL_DETAIL output
		 * type
		 */
		LOW,

		/**
		 * Medium fields are included in multi line summary type output
		 */
		MEDIUM
	}

	public interface Resolver {
		public boolean canBeResolved(byte[] address);

		public boolean isCached(byte[] address);

		public String resolve(byte[] address);
	}

	/**
	 * Various output formatting styles for JField values
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Style {
		BYTE_ARRAY_ARRAY_IP4_ADDRESS,
		BYTE_ARRAY_COLON_ADDRESS,
		BYTE_ARRAY_DASH_ADDRESS,

		BYTE_ARRAY_DOT_ADDRESS,
		BYTE_ARRAY_HEX_DUMP,
		BYTE_ARRAY_HEX_DUMP_ADDRESS,
		BYTE_ARRAY_HEX_DUMP_NO_ADDRESS,

		BYTE_ARRAY_HEX_DUMP_NO_TEXT,
		BYTE_ARRAY_HEX_DUMP_NO_TEXT_ADDRESS,

		BYTE_ARRAY_HEX_DUMP_TEXT,
		BYTE_ARRAY_IP4_ADDRESS,
		BYTE_ARRAY_IP6_ADDRESS,
		INT_BIN,
		INT_BITS,
		INT_DEC,
		/**
		 * Integer is converted to a hex with a preceding 0x in front
		 */
		INT_HEX,
		INT_OCT,
		INT_RADIX_10,
		/**
		 * Integer is convert to a hex without a preceding 0x in front
		 */
		INT_RADIX_16,
		INT_RADIX_2,
		INT_RADIX_8,
		LONG_DEC,

		LONG_HEX,
		STRING,
		STRING_TEXT_DUMP,
	}

	private static final Detail DEFAULT_DETAIL = Detail.MULTI_LINE_FULL_DETAIL;

	private static boolean defaultDisplayPayload = true;

	private static boolean defaultResolveAddresses = false;

	private static JFormatter global;

	private final static Map<Integer, String> OUI_CACHE =
	    new HashMap<Integer, String>();

	/**
	 * Gets the default formatter
	 * 
	 * @return default formatter
	 */
	public static JFormatter getDefault() {
		if (global == null) {
			global = new XmlFormatter();
		}

		return global;
	}

	private static void readOuisFromCompressedIEEEDb(BufferedReader in)
	    throws IOException {
		try {
			String s;
			while ((s = in.readLine()) != null) {
				String[] c = s.split(":");
				if (c.length < 2) {
					continue;
				}

				int i = Integer.parseInt(c[0], 16);

				OUI_CACHE.put(i, c[1]);

			}
		} finally {
			in.close(); // Make sure we close the file
		}
	}

	private static boolean readOuisFromCompressedIEEEDb(String f)
	    throws FileNotFoundException, IOException {
		/*
		 * Try local file first, more efficient
		 */
		File file = new File(f);
		if (file.canRead()) {
			readOuisFromCompressedIEEEDb(new BufferedReader(new FileReader(file)));
			return true;
		}

		/*
		 * Otherwise look for it in classpath
		 */
		InputStream in =
		    JFormatter.class.getClassLoader().getResourceAsStream("resources/" + f);
		if (in == null) {
			return false; // Can't find it
		}
		readOuisFromCompressedIEEEDb(new BufferedReader(new InputStreamReader(in)));

		return true;
	}

	private static void readOuisFromRawIEEEDb(BufferedReader in)
	    throws IOException {
		try {
			String s;
			while ((s = in.readLine()) != null) {
				if (s.contains("(base 16)")) {
					String[] c = s.split("\t\t");
					if (c.length < 2) {
						continue;
					}

					String p = c[0].split(" ")[0];
					int i = Integer.parseInt(p, 16);
					String[] a = c[1].split(" ");

					if (a.length > 0) {
						OUI_CACHE.put(i, a[0]);
					}
				}
			}
		} finally {
			in.close(); // Make sure we close the file
		}
	}

	private static void readOuisFromRawIEEEDb(File f) throws IOException {
		readOuisFromRawIEEEDb(new BufferedReader(new FileReader(f)));
	}

	private static boolean readOuisFromRawIEEEDb(String f) throws IOException {
		/*
		 * Try local file first, more efficient
		 */
		File file = new File(f);
		if (file.canRead()) {
			readOuisFromRawIEEEDb(file);
			return true;

		}

		InputStream in;
		try {
			URL web = new URL("http://standards.ieee.org/regauth/oui/oui.txt");
			in = web.openStream();
			readOuisFromRawIEEEDb(new BufferedReader(new InputStreamReader(in)));
			saveCompressedIEEEDb();

			return true;
		} catch (Exception e) {
			// Do nothing, we failed, try classpath
		}

		/*
		 * Otherwise look for it in classpath
		 */
		in =
		    JFormatter.class.getClassLoader().getResourceAsStream("resources/" + f);
		if (in == null) {
			return false; // Can't find it
		}
		readOuisFromRawIEEEDb(new BufferedReader(new InputStreamReader(in)));

		saveCompressedIEEEDb();

		return true;
	}

	private static void saveCompressedIEEEDb() throws IOException {
		Writer w = new FileWriter(new File("oui.txt"));
		try {
			for (int i : OUI_CACHE.keySet()) {
				w.append(Integer.toHexString(i) + ":" + OUI_CACHE.get(i) + "\n");
			}
		} finally {
			w.close();
		}
	}

	/**
	 * @param formatter
	 */
	public static void setDefault(JFormatter formatter) {
		global = formatter;
	}

	/**
	 * Sets a global flag that will enable or disable display of payload header in
	 * a packet. If packet contains a payload header at the end of the packet this
	 * flag determines if the header is displayed along with the rest of the
	 * display or not. The default is to enable. This method sets a global flag
	 * for all new formatters. Any existing formatters already instantiated will
	 * not have their flag changed by this global method.
	 * 
	 * @param enable
	 *          true will enable display of payload header otherwise disable
	 * @see #setDisplayPayload(boolean)
	 */
	public static void setDefaultDisplayPayload(boolean enable) {
		JFormatter.defaultDisplayPayload = enable;
	}

	public static void setDefaultResolveAddress(boolean enable) {
		JFormatter.defaultResolveAddresses = enable;
	}

	private Detail[] detailsPerHeader = new Detail[JRegistry.MAX_ID_COUNT];

	private boolean displayPayload;

	protected int frameIndex = -1;

	private JHeaderPool headers = new JHeaderPool();

	private IpResolver ipResolver;

	private int level;

	protected Formatter out;

	private StringBuilder outputBuffer;

	private Stack<String> padStack = new Stack<String>();

	private boolean resolveAddresses = false;

	/**
	 * 
	 */
	public JFormatter() {
		setDetail(DEFAULT_DETAIL);

		setOutput(System.out);

		setResolveAddresses(defaultResolveAddresses);
		setDisplayPayload(defaultDisplayPayload);
	}

	/**
	 * Creates a formatter.
	 * 
	 * @param out
	 *          appendable device where to send output
	 */
	public JFormatter(Appendable out) {
		setDetail(DEFAULT_DETAIL);
		setOutput(out);
		setResolveAddresses(defaultResolveAddresses);
		setDisplayPayload(defaultDisplayPayload);
	}

	/**
	 * Creates a formatter.
	 * 
	 * @param out
	 *          buffer where to send output
	 */
	public JFormatter(StringBuilder out) {

		setDetail(DEFAULT_DETAIL);
		setOutput(out);
		setResolveAddresses(defaultResolveAddresses);
		setDisplayPayload(defaultDisplayPayload);
	}

	/**
	 * 
	 */
	protected void decLevel() {
		this.level--;
		padStack.pop();
	}

	/**
	 * @param header
	 * @param field
	 * @param detail
	 * @throws IOException
	 */
	protected abstract void fieldAfter(JHeader header, JField field, Detail detail)
	    throws IOException;

	/**
	 * @param header
	 * @param field
	 * @param detail
	 * @throws IOException
	 */
	protected abstract void fieldBefore(
	    JHeader header,
	    JField field,
	    Detail detail) throws IOException;

	public void format(JHeader header) throws IOException {
		format(header, DEFAULT_DETAIL);
	}

	/**
	 * @param header
	 * @param detail
	 * @throws IOException
	 */
	@SuppressWarnings("unchecked")
	public void format(JHeader header, Detail detail) throws IOException {
		final JField[] fields = header.getFields();

		headerBefore(header, detail);

		for (final JField field : fields) {

			if (field.hasField(header) == false) {
				continue;
			}

			format(header, field, detail);
		}

		for (JHeader subHeader : header.getSubHeaders()) {
			format(header, subHeader, detail);
		}

		headerAfter(header, detail);

	}

	public void format(JHeader header, JField field) throws IOException {
		format(header, field, DEFAULT_DETAIL);
	}

	/**
	 * @param header
	 * @param field
	 * @param detail
	 * @throws IOException
	 */
	public void format(JHeader header, JField field, Detail detail)
	    throws IOException {

		fieldBefore(header, field, detail);

		if (field.hasSubFields()) {
			for (JField sub : field.getSubFields()) {
				format(header, sub, detail);
			}
		}

		fieldAfter(header, field, detail);

	}

	@SuppressWarnings("unchecked")
	public void format(JHeader header, JHeader subHeader, Detail detail)
	    throws IOException {

		final JField[] fields = subHeader.getFields();

		subHeaderBefore(header, subHeader, detail);

		for (final JField field : fields) {

			if (field == null) {
				continue; // DEBUGING skip nulls for now
			}

			if (field.hasField(header) == false) {
				continue;
			}

			format(subHeader, field, detail);

		}

		subHeaderAfter(header, subHeader, detail);
	}

	/**
	 * @param packet
	 * @throws IOException
	 */
	public void format(JPacket packet) throws IOException {
		format(packet, DEFAULT_DETAIL);
	}

	/**
	 * Formats a packet for output
	 * 
	 * @param packet
	 *          packet to format
	 * @param detail
	 *          detail level
	 * @throws IOException
	 *           any IO errors when sending data to default output device
	 */
	public void format(JPacket packet, Detail detail) throws IOException {

		packetBefore(packet, detail);

		final int count = packet.getHeaderCount();
		for (int i = 0; i < count; i++) {

			final int id = packet.getHeaderIdByIndex(i);
			if (id == JProtocol.PAYLOAD_ID && displayPayload == false) {
				continue;
			}

			try {
				final JHeader header = headers.getHeader(id);
				final Detail headerDetail =
				    (detailsPerHeader[id] == null) ? detail : detailsPerHeader[id];

				packet.getHeaderByIndex(i, header);
				if (header.getLength() == 0) {
					continue;
				}

				format(header, headerDetail);
			} catch (UnregisteredHeaderException e) {
				throw new IllegalStateException(e); // Serious internal error
			}
		}

		packetAfter(packet, detail);
	}

	/**
	 * Formats a packet for output
	 * 
	 * @param out
	 *          string buffer to send output to
	 * @param packet
	 *          packet to format
	 */
	public void format(StringBuilder out, JPacket packet) {

		try {
			format(packet, DEFAULT_DETAIL);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	private String formatIpAddress(byte[] address) {

		if (resolveAddresses) {
			return resolveIp(address);
		}

		return (address.length == 16) ? FormatUtils.asStringIp6(address, true)
		    : FormatUtils.asString(address, '.', 10).toUpperCase();
	}

	private String formatMacAddress(byte[] address) {

		String f = FormatUtils.asString(address, ':').toLowerCase();

		int i =
		    ((address[2] < 0) ? address[2] + 256 : address[2])
		        | ((address[1] < 0) ? address[1] + 256 : address[1]) << 8
		        | ((address[0] < 0) ? address[0] + 256 : address[0]) << 16;

		if (resolveAddresses && OUI_CACHE.containsKey(i)) {
			byte[] a = new byte[3];
			a[0] = address[3];
			a[1] = address[4];
			a[2] = address[5];

			String s =
			    OUI_CACHE.get(i) + "_" + FormatUtils.asString(a, ':').toLowerCase();
			return s + " (" + f + ")";
		}

		return f;
	}

	/**
	 * Called as the last step after the header has been formatted
	 * 
	 * @param header
	 *          headercurrently being formatted
	 * @param detail
	 *          detail level to include
	 * @throws IOException
	 *           any IO errors while sending data to output device
	 */
	protected abstract void headerAfter(JHeader header, Detail detail)
	    throws IOException;

	/**
	 * Called as the first step before the header has been formatted
	 * 
	 * @param header
	 *          headercurrently being formatted
	 * @param detail
	 *          detail level to include
	 * @throws IOException
	 *           any IO errors while sending data to output device
	 */
	protected abstract void headerBefore(JHeader header, Detail detail)
	    throws IOException;

	/**
	 * Increment the padding level using default padding string
	 * 
	 * @param count
	 *          numer of pad strings to pad
	 */
	protected void incLevel(int count) {
		incLevel(count, ' ');
	}

	/**
	 * @param count
	 * @param c
	 */
	protected void incLevel(int count, char c) {
		StringBuilder b = new StringBuilder();

		for (int i = 0; i < count; i++) {
			b.append(c);
		}

		incLevel(b.toString());
	}

	/**
	 * @param pad
	 */
	protected void incLevel(String pad) {
		this.level++;
		padStack.push(pad);
	}

	public abstract void packetAfter(JPacket packet, Detail detail)
	    throws IOException;

	public abstract void packetBefore(JPacket packet, Detail detail)
	    throws IOException;

	/**
	 * Appends a string, a pad, to the beginning of the line.
	 * 
	 * @return this formatter
	 */
	protected Formatter pad() {

		this.out.format("\n");

		for (String s : padStack) {
			this.out.format(String.valueOf(s));
		}

		return this.out;
	}

	/**
	 * If the current output device is a StringBuilder, it resets the buffer.
	 * Otherwise this method does nothing.
	 */
	public void reset() {
		if (outputBuffer != null) {
			outputBuffer.setLength(0);
		}
	}

	/**
	 * Performs an IP address resolution. This method is not dependent of the
	 * boolean address resolution flags.
	 * 
	 * @param address
	 *          address to convert
	 * @return formatted string with the address resolved or address and a failure
	 *         message
	 */
	private String resolveIp(byte[] address) {
		if (ipResolver == null) {
			ipResolver = new IpResolver();
		}

		String f =
		    (address.length == 16) ? FormatUtils.asStringIp6(address, true)
		        : FormatUtils.asString(address, '.', 10).toUpperCase();
		String name = ipResolver.resolve(address);

		if (name == null) {
			return f + " (resolve failed)";

		} else {
			return f + " (" + name + ")";
		}
	}

	/**
	 * Changes the detail level that is displayed with formatted output
	 * 
	 * @param detail
	 *          the level of detail to set for all headers
	 */
	public void setDetail(Detail detail) {
		for (int i = 0; i < JRegistry.MAX_ID_COUNT; i++) {
			detailsPerHeader[i] = detail;
		}
	}

	/**
	 * Changes the detail level that is displayed for formatted output for a
	 * specific header type.
	 * 
	 * @param detail
	 *          the level of detail set for this particular header
	 * @param id
	 *          header id
	 */
	public void setDetail(Detail detail, int id) {
		detailsPerHeader[id] = detail;
	}

	/**
	 * Sets weather the payload header will be part of the display of a packet.
	 * This is an instance method that defaults the global setting. You can change
	 * this flag on an instance by instance basis.
	 * 
	 * @param enable
	 *          if true will include payload header in the display, otherwise it
	 *          will not
	 * @see #setDefaultDisplayPayload(boolean)
	 */
	public void setDisplayPayload(boolean enable) {
		this.displayPayload = enable;
	}

	/**
	 * Sets the packet frame number, as an index. This value will be used in
	 * display of the header. Once set to a value of 0 or more, it will be
	 * automatically incremented for every new packet frame displayed. It can be
	 * also set to new value between each format call.
	 * 
	 * @param index
	 *          initial index for frame number
	 */
	public void setFrameIndex(int index) {
		this.frameIndex = index;
	}

	/**
	 * Changes the output device for this formatter. Output produced will be sent
	 * to the specified device.
	 * 
	 * @param out
	 *          new formatter device
	 */
	public void setOutput(Appendable out) {
		this.out = new Formatter(out);
		this.outputBuffer = null;
	}

	/**
	 * Changes the output device for this formatter. Output produced will be sent
	 * to the specified device.
	 * 
	 * @param out
	 *          new formatter device
	 */
	public void setOutput(StringBuilder out) {
		this.outputBuffer = out;
		this.out = new Formatter(out);
	}

	/**
	 * Sets a flag which will enable address resolutions. This is an instance
	 * method setter that will change the flag only for this instance of the
	 * formatter. The default is set to global default which is set using
	 * {@link #setDefaultResolveAddress(boolean)}.
	 * 
	 * @param enable
	 *          true to enable address resolution, otherwise false
	 * @see #setDefaultResolveAddress(boolean)
	 */
	public void setResolveAddresses(boolean enable) {
		resolveAddresses = enable;

		if (enable == true && OUI_CACHE.isEmpty()) {
			try {
				if (readOuisFromCompressedIEEEDb("oui.txt") == false) {
					readOuisFromRawIEEEDb("ieee-oui.txt");
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	@SuppressWarnings("unchecked")
	private String stylizeBitField(JHeader header, JField field, Object value) {
		StringBuilder b = new StringBuilder();
		final JField parent = field.getParent();
		final int plen = parent.getLength(header);
		// final int p = parent.getValue(int.class, header);
		final long pmask = parent.getMask(header);
		long v = field.getValue(Number.class, header).longValue();

		final int offset = field.getOffset(header);
		final int length = field.getLength(header);

		final int end = (offset + length);
		final int start = offset;

		for (int i = plen; i > end; i--) {
			if ((pmask & (1L << (i - 1))) == 0) {
				continue;
			}

			b.append(((i - 1) % 4) == 0 ? ". " : '.');
		}

		for (int i = end; i > start; i--) {
			if ((pmask & (1L << (i - 1))) == 0) {
				continue;
			}

			if ((v & (1L << (i - start - 1))) == 0) {
				b.append('0');
			} else {
				b.append('1');
			}

			if (((i - 1) % 4) == 0) {
				b.append(' ');
			}
		}

		for (int i = start; i > 0; i--) {
			if ((pmask & (1L << (i - 1))) == 0) {
				continue;
			}
			b.append(((i - 1) % 4) == 0 ? ". " : '.');
		}

		/*
		 * Hack since we always append 1 too many ' ' chars.
		 */
		b.setLength(b.length() - 1);

		// for (int i = plen - 1; i >= 0; i--) {
		//		
		// if (i >= start && i < end) {
		// b.append('0');
		// } else {
		// b.append('.');
		// }
		//
		// if ((i % 4) == 0) {
		// b.append(' ');
		// }
		// }

		return b.toString();
	}

	/**
	 * @param header
	 * @param field
	 * @param value
	 * @return
	 */
	protected String[] stylizeMultiLine(JHeader header, JField field, Object value) {
		return stylizeMultiLine(header, field, field.getStyle(), value);
	}

	protected String[] stylizeMultiLine(
	    JHeader header,
	    JField field,
	    Style style,
	    Object value) {

		switch (style) {
			case BYTE_ARRAY_HEX_DUMP:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0, true,
				    true, true);

			case BYTE_ARRAY_HEX_DUMP_NO_TEXT:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0, true,
				    false, true);

			case BYTE_ARRAY_HEX_DUMP_NO_TEXT_ADDRESS:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0,
				    false, false, true);

			case BYTE_ARRAY_HEX_DUMP_NO_ADDRESS:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0,
				    false, true, true);

			case BYTE_ARRAY_HEX_DUMP_ADDRESS:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0, true,
				    false, false);

			case BYTE_ARRAY_HEX_DUMP_TEXT:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0,
				    false, true, false);

			case STRING_TEXT_DUMP:
				return ((String) value).split("\r\n");

			default:
				return new String[] { stylizeSingleLine(header, field, value) };
		}
	}

	/**
	 * @param header
	 * @param field
	 * @param value
	 * @return
	 */
	protected String stylizeSingleLine(JHeader header, JField field, Object value) {

		final Style style = field.getStyle();

		switch (style) {
			case BYTE_ARRAY_DASH_ADDRESS:
				return FormatUtils.asString((byte[]) value, '-').toUpperCase();

			case BYTE_ARRAY_COLON_ADDRESS:
				return formatMacAddress((byte[]) value);

			case BYTE_ARRAY_DOT_ADDRESS:
				return FormatUtils.asString((byte[]) value, '.').toUpperCase();

			case BYTE_ARRAY_ARRAY_IP4_ADDRESS:
			case BYTE_ARRAY_IP4_ADDRESS:
			case BYTE_ARRAY_IP6_ADDRESS:
				return formatIpAddress((byte[]) value);

			case INT_BITS:
				return stylizeBitField(header, field, value);

			case INT_RADIX_16:
				return Long.toHexString(((Number) value).longValue()).toUpperCase();

			case INT_HEX:
				return "0x"
				    + Long.toHexString(((Number) value).longValue()).toUpperCase()
				    + " (" + value.toString() + ")";

			case LONG_HEX:
				return "0x" + Long.toHexString((long) (Long) value).toUpperCase()
				    + " (" + value.toString() + ")";

			default:
				return value.toString();
		}
	}

	/**
	 * @param header
	 * @param subHeader
	 * @param detail
	 * @throws IOException
	 */
	protected abstract void subHeaderAfter(
	    JHeader header,
	    JHeader subHeader,
	    Detail detail) throws IOException;

	/**
	 * @param header
	 * @param subHeader
	 * @param detail
	 * @throws IOException
	 */
	protected abstract void subHeaderBefore(
	    JHeader header,
	    JHeader subHeader,
	    Detail detail) throws IOException;

	public String toString() {
		return this.out.toString();
	}

}
