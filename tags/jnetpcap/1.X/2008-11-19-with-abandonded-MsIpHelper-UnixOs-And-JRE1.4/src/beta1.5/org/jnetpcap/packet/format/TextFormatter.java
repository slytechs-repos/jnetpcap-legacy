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

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TextFormatter
    extends JFormatter {

	private final static String FIELD_FORMAT = "%16s = ";

	/*
	 * Utility Formatter
	 */
	final Formatter uf = new Formatter();

	protected void fieldAfter(JHeader header, JField field, Detail detail)
	    throws IOException {

		if (field.getStyle() == Style.INT_BITS) {

		} else if (field.isCompound()) {
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

		if (field.isCompound()) {
			final String v = stylizeSingleLine(header, field, runtime.value(header));
			pad().format(FIELD_FORMAT + "%s", field.getName(), v);
			incLevel(19);

		} else if (field.getStyle() == Style.INT_BITS) {

			final JBitField bits = (JBitField) field;
			final JFieldRuntime<JHeader, Object> bitsRuntime =
			    (JFieldRuntime<JHeader, Object>) bits.getRuntime();

			final String v = stylizeSingleLine(header, field, runtime.value(header));
			final String d = bitsRuntime.valueDescription(header);
			final int i = (Integer) runtime.value(header);
			pad().format("%s = [%d] %s%s", v, i, field.getName(),
			    ((d == null) ? "" : ": " + d));

		} else if (field.getStyle() == Style.BYTE_ARRAY_HEX_DUMP) {
			final String[] v = stylizeMultiLine(header, field, runtime.value(header));
			for (String i : v) {
				pad().format("%s", i);
			}

		} else {

			final String v = stylizeSingleLine(header, field, runtime.value(header));
			final String description = runtime.valueDescription(header);
			final String units = field.getUnits();
						
			pad().format(FIELD_FORMAT + "%s", field.getName(), v);
			
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
	}

	protected void headerBefore(JHeader header, Detail detail) throws IOException {

		final String name = header.getName();
		incLevel(name + ": ");

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

}
