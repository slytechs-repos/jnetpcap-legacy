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

import java.io.IOException;
import java.util.Formatter;
import java.util.Stack;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.UnregisteredHeaderException;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.util.resolver.Resolver;
import org.jnetpcap.util.resolver.Resolver.ResolverType;

/**
 * Formats decoded contents of a JPacket for output.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JFormatter {

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
		MULTI_LINE_FULL_DETAIL {
			public boolean isDisplayable(Priority priority) {
				return true;
			}

		},

		/**
		 * Summary of one major component per line
		 */
		MULTI_LINE_SUMMARY {
			public boolean isDisplayable(Priority priority) {
				return priority == Priority.MEDIUM || priority == Priority.HIGH;
			}

		},

		/**
		 * Supress output
		 */
		NONE {
			public boolean isDisplayable(Priority priority) {
				return false;
			}

		},

		/**
		 * Compress output to a single line of output for the entire component
		 */
		ONE_LINE_SUMMARY {
			public boolean isDisplayable(Priority priority) {
				return priority == Priority.HIGH;
			}

		};

		/**
		 * @param priority
		 * @return
		 */
		public abstract boolean isDisplayable(Priority priority);
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
		BOOLEAN, STRING_ARRAY,
	}

	private static final Detail DEFAULT_DETAIL = Detail.MULTI_LINE_FULL_DETAIL;

	private static boolean defaultDisplayPayload = true;

	private static boolean defaultResolveAddresses = false;

	private static JFormatter global;

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

	private Resolver ipResolver;

	private int level;

	private Resolver ouiPrefixResolver;

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
		if (this.level == 0) {
			return;
		}

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

	/**
	 * @param packet
	 * @param detail
	 */
	protected void fieldNull(JHeader header, JField field, Detail detail) {
		/* Do nothing by default */
	}

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
		if (header == null) {
			headerNull(header, detail);
			return;
		}

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

		if (header == null) {
			headerNull(header, detail);
			return;
		}

		if (field == null) {
			fieldNull(header, field, detail);
			return;
		}

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

			if (field == null || detail.isDisplayable(field.getPriority()) == false) {
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

		if (packet == null) {
			packetNull(packet, detail);
			return;
		}

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

		if (resolveAddresses && ouiPrefixResolver.canBeResolved(address)) {
			String prefix = ouiPrefixResolver.resolve(address);
			String s =
			    prefix + "_"
			        + FormatUtils.asString(address, ':', 16, 3, 3).toLowerCase();
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
	 * @param packet
	 * @param detail
	 */
	protected void headerNull(JHeader header, Detail detail) {
		/* Do nothing by default */
	}

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
	 * @param packet
	 * @param detail
	 */
	protected void packetNull(JPacket packet, Detail detail) {
		/* Do nothing by default */
	}

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
		
		this.padStack.clear();
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

		if (enable == true && ouiPrefixResolver == null) {
			this.ouiPrefixResolver =
			    JRegistry.getResolver(ResolverType.IEEE_OUI_PREFIX);
			this.ipResolver = JRegistry.getResolver(ResolverType.IP);
		} else {
			ouiPrefixResolver = null;
			ipResolver = null;
		}
	}

	@SuppressWarnings("unchecked")
	private String stylizeBitField(JHeader header, JField field, Object value) {
		StringBuilder b = new StringBuilder();
		final JField parent = field.getParent();
		final int plen = parent.getLength(header);
		// final int p = parent.getValue(int.class, header);
		final long pmask = parent.getMask(header);
		long v = field.longValue(header);

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

	/**
	 * @param text
	 */
	public void println(String text) {
		out.format("%s\n", text);
	}

	/**
	 * @param text
	 */
	public void printf(String format, Object... args) {
		out.format(format, args);
	}

}
