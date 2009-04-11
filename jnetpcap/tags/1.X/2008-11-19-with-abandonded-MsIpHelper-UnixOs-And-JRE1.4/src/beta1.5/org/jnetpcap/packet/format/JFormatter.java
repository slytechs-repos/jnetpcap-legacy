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

/**
 * Formats decoded contents of a JPacket for output.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class JFormatter {

	/**
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Detail {
		MULTI_LINE_FULL_DETAIL,
		MULTI_LINE_SUMMARY,
		NONE,
		ONE_LINE_SUMMARY,
	}

	/**
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Priority {
		HIGH,
		LOW,
		MEDIUM
	}

	/**
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public enum Style {
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
	}

	private static final Detail DEFAULT_DETAIL = Detail.MULTI_LINE_FULL_DETAIL;

	private static JFormatter global;

	/**
	 * @return
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

	private Detail[] detailsPerHeader = new Detail[JRegistry.MAX_ID_COUNT];

	protected int frameIndex;

	private JHeaderPool headers = new JHeaderPool();

	private int level;

	protected Formatter out = new Formatter(System.out);

	private Stack<String> padStack = new Stack<String>();

	/**
	 * 
	 */
	public JFormatter() {
		setDetail(Detail.MULTI_LINE_FULL_DETAIL);

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
	protected abstract void fieldBefore(JHeader header, JField field,
	    Detail detail) throws IOException;

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

			final JFieldRuntime<JHeader, Object> runtime =
			    (JFieldRuntime<JHeader, Object>) field.getRuntime();

			if (runtime.hasField(header) == false) {
				continue;
			}

			format(header, field, detail);

		}

		headerAfter(header, detail);

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

		if (field.isCompound()) {
			for (JField sub : field.getCompoundFields()) {
				format(header, sub, detail);
			}
		}

		fieldAfter(header, field, detail);

	}

	/**
	 * @param packet
	 * @throws IOException
	 */
	public void format(JPacket packet) throws IOException {
		format(packet, Detail.MULTI_LINE_FULL_DETAIL);
	}

	/**
	 * @param out
	 * @param packet
	 * @return
	 * @throws IOException
	 */
	public void format(JPacket packet, Detail detail) throws IOException {

		packetBefore(packet, detail);

		final int count = packet.getHeaderCount();
		for (int i = 0; i < count; i++) {

			final int id = packet.getHeaderIdByIndex(i);
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
	 * @param out
	 * @param packet
	 * @return
	 */
	public void format(StringBuilder out, JPacket packet) {

		try {
			format(packet, DEFAULT_DETAIL);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * @param header
	 * @param detail
	 * @throws IOException
	 */
	protected abstract void headerAfter(JHeader header, Detail detail)
	    throws IOException;

	/**
	 * @param header
	 * @param detail
	 * @throws IOException
	 */
	protected abstract void headerBefore(JHeader header, Detail detail)
	    throws IOException;

	/**
	 * @param count
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
	 * @return
	 */
	protected Formatter pad() {

		this.out.format("\n");

		for (String s : padStack) {
			this.out.format(s);
		}

		return this.out;
	}

	/**
	 * @param detail
	 */
	public void setDetail(Detail detail) {
		for (int i = 0; i < JRegistry.MAX_ID_COUNT; i++) {
			detailsPerHeader[i] = detail;
		}
	}

	/**
	 * @param detail
	 * @param id
	 */
	public void setDetail(Detail detail, int id) {
		detailsPerHeader[id] = detail;
	}

	/**
	 * @param index
	 */
	public void setFrameIndex(int index) {
		this.frameIndex = index;
	}

	/**
	 * @param name
	 * @param nicname
	 */
	public void setHeaderName(String name, String nicname) {
	}

	/**
	 * @param out
	 */
	public void setOutput(Appendable out) {
		this.out = new Formatter(out);
	}

	@SuppressWarnings("unchecked")
	private String stylizeBitField(JHeader header, JField field, Object value) {
		StringBuilder b = new StringBuilder();
		final JBitField bits = (JBitField) field;
		final JField parent = bits.getParent();
		final JFieldRuntime<JHeader, Object> pruntime =
		    (JFieldRuntime<JHeader, Object>) parent.getRuntime();
		final JFieldRuntime<JHeader, Object> runtime =
		    (JFieldRuntime<JHeader, Object>) bits.getRuntime();
		final int len = parent.getRuntime().getLength();
		final int p = (int) (Integer) pruntime.value(header);
		final int mask = runtime.getMask();

		for (int i = len - 1; i >= 0; i--) {
			int m = (mask >> i) & 0x1;
			if (m == 0) {
				b.append('.');
			} else {
				if ((p & (m << i)) == 0) {
					b.append('0');
				} else {
					b.append('1');
				}
			}

			if ((i % 4) == 0) {
				b.append(' ');
			}
		}

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

	protected String[] stylizeMultiLine(JHeader header, JField field,
	    Style style, Object value) {

		switch (style) {
			case BYTE_ARRAY_HEX_DUMP:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0, true,
				    true, true);

			case BYTE_ARRAY_HEX_DUMP_NO_TEXT:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0, true,
				    false, true);

			case BYTE_ARRAY_HEX_DUMP_NO_TEXT_ADDRESS:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0, false,
				    false, true);

			case BYTE_ARRAY_HEX_DUMP_NO_ADDRESS:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0, false,
				    true, true);

			case BYTE_ARRAY_HEX_DUMP_ADDRESS:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0, true,
				    false, false);

			case BYTE_ARRAY_HEX_DUMP_TEXT:
				return FormatUtils.hexdump((byte[]) value, header.getOffset(), 0, false,
				    true, false);

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
				return FormatUtils.asString((byte[]) value, ':').toUpperCase();

			case BYTE_ARRAY_DOT_ADDRESS:
				return FormatUtils.asString((byte[]) value, '.').toUpperCase();

			case BYTE_ARRAY_IP4_ADDRESS:
				return FormatUtils.asString((byte[]) value, '.', 10).toUpperCase();

			case BYTE_ARRAY_IP6_ADDRESS:
				return FormatUtils.asStringIp6((byte[]) value, true).toUpperCase();

			case INT_BITS:
				return stylizeBitField(header, field, value);

			case INT_RADIX_16:
				return Integer.toHexString((int) (Integer) value).toUpperCase();

			case INT_HEX:
				return "0x" + Integer.toHexString((int) (Integer) value).toUpperCase()
				    + " (" + value.toString() + ")";

			case LONG_HEX:
				return "0x" + Long.toHexString((long) (Long) value).toUpperCase()
				    + " (" + value.toString() + ")";

			default:
				return value.toString();
		}
	}

}
