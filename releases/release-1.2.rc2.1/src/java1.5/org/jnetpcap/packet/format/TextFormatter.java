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

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.packet.structure.JFieldRuntime;

/**
 * Formatter that formats packet content for human readable output. This class
 * produces pretty text based output by reading field objects from the header.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TextFormatter
    extends JFormatter {

	private final static String FIELD_FORMAT = "%16s = ";
	private final static String FIELD_ARRAY_FORMAT = "%16s[%d] = ";

	private static final String SEPARATOR = ": ";

	/*
	 * Utility Formatter
	 */
	final Formatter uf = new Formatter();

	/**
	 * Creates a text formatter which sends its output to a string buffer
	 * 
	 * @param out
	 *          buffer where to send output
	 */
	public TextFormatter(StringBuilder out) {
		super(out);
	}

	/**
	 * Creates a test formatter which send its output to an appendable output
	 * device
	 * 
	 * @param out
	 *          where to send output
	 */
	public TextFormatter(Appendable out) {
		super(out);
	}

	/**
	 * 
	 */
	public TextFormatter() {
	}

	protected void fieldAfter(JHeader header, JField field, Detail detail)
	    throws IOException {

		if (field.getStyle() == Style.INT_BITS) {

		} else if (field.hasSubFields()) {
			decLevel();
		} else if (field.getStyle() != Style.BYTE_ARRAY_HEX_DUMP) {
			decLevel();
		}
	}

	@SuppressWarnings("unchecked")
	protected void fieldBefore(JHeader header, JField field, Detail detail)
	    throws IOException {

		final JFieldRuntime<JHeader, Object> runtime =
		    (JFieldRuntime<JHeader, Object>) field.getRuntime();

		if (field.hasSubFields()) {
			final String v = stylizeSingleLine(header, field, field.getValue(header));
			pad().format(FIELD_FORMAT + "%s", field.getDisplay(), v);
			incLevel(19);

		} else if (field.getStyle() == Style.INT_BITS) {

			final JFieldRuntime<JHeader, Object> bitsRuntime =
			    (JFieldRuntime<JHeader, Object>) field.getRuntime();

			final String v = stylizeSingleLine(header, field, field.getValue(header));
			final String d = bitsRuntime.valueDescription(header);
			final int i = (Integer) field.getValue(header);
			pad().format("%s = [%d] %s%s", v, i, field.getDisplay(),
			    ((d == null) ? "" : ": " + d));

		} else if (field.getStyle() == Style.BYTE_ARRAY_HEX_DUMP) {
			final String[] v = stylizeMultiLine(header, field, field.getValue(header));
			for (String i : v) {
				pad().format("%s", i);
			}

		} else if (field.getStyle() == Style.BYTE_ARRAY_ARRAY_IP4_ADDRESS) {
			byte[][] table = (byte[][]) field.getValue(header);

			int i = 0;
			for (byte[] b : table) {
				final String v = stylizeSingleLine(header, field, b);
				pad().format(FIELD_ARRAY_FORMAT  + "%s", field.getDisplay(), i++, v);
			}

			incLevel(0); // Inc for multi line fields
		} else {

			final String v = stylizeSingleLine(header, field, field.getValue(header));
			final String description = runtime.valueDescription(header);
			final String units = field.getUnits();

			pad().format(FIELD_FORMAT + "%s", field.getDisplay(), v);

			if (units != null) {
				out.format(" " + units);
			}

			if (description != null) {
				out.format(" [" + description + "]");
			}

			incLevel(19); // Inc for multi line fields

		}

	}

	protected void headerAfter(JHeader header, Detail detail) throws IOException {
		pad();

		decLevel();
		decLevel();
	}

	protected void headerBefore(JHeader header, Detail detail) throws IOException {

		final String name = header.getName();
		incLevel(name);
		incLevel(SEPARATOR);

		pad().format(" ******* %s (%s) offset=%d length=%d", header.getName(),
		    header.getNicname(), header.getOffset(), header.getLength());
		pad();

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#packetAfter(org.jnetpcap.packet.JPacket,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	public void packetAfter(JPacket packet, Detail detail) throws IOException {
		if (frameIndex != -1) {
			pad().format("END OF PACKET %d", frameIndex);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#packetBefore(org.jnetpcap.packet.JPacket,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	public void packetBefore(JPacket packet, Detail detail) throws IOException {
		pad();
		if (frameIndex != -1) {
			pad().format("START OF PACKET %d", frameIndex);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#subHeaderAfter(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void subHeaderAfter(JHeader header, JHeader subHeader, Detail detail)
	    throws IOException {

		// decLevel();
		// decLevel();
		//		
		// incLevel(SEPARATOR);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#subHeaderBefore(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void subHeaderBefore(
	    JHeader header,
	    JHeader subHeader,
	    Detail detail) throws IOException {
		pad();
		// decLevel();
		//		
		// incLevel(":" + subHeader.getNicname());
		// incLevel(SEPARATOR);

		pad().format("+ %s: offset=%d length=%d", subHeader.getName(),
		    subHeader.getOffset(), subHeader.getLength());
	}
}
