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

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.packet.structure.JFieldRuntime;

/**
 * This formatter products XML output for a packet. A packet content is output
 * as XML sheet based on field objects read from each header within a packet.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class XmlFormatter
    extends JFormatter {

	private static final String PAD = "  ";

	private static final String LT = "<";

	private static final String GT = ">";

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#end(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JField,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@SuppressWarnings("unchecked")
	@Override
	protected void fieldAfter(JHeader header, JField field, Detail detail)
	    throws IOException {

		final JFieldRuntime<JHeader, Object> runtime =
		    (JFieldRuntime<JHeader, Object>) field.getRuntime();

		if (field.getStyle() == Style.BYTE_ARRAY_HEX_DUMP) {
			decLevel();
			pad().format(LT + "/hexdump" + GT + "\n");
		} else if (false && field.hasSubFields()) {
			final String v = stylizeSingleLine(header, field, runtime.value(header));

			pad().format(LT + "/field" + GT);

		} else if (field.getStyle() == Style.INT_BITS) {
		}

		decLevel();
	}

	/**
	 * 
	 */
	public XmlFormatter() {
		super();
	}

	/**
	 * @param out
	 */
	public XmlFormatter(Appendable out) {
		super(out);
	}

	/**
	 * @param out
	 */
	public XmlFormatter(StringBuilder out) {
		super(out);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#start(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JField,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@SuppressWarnings("unchecked")
	@Override
	protected void fieldBefore(JHeader header, JField field, Detail detail)
	    throws IOException {

		final JFieldRuntime<JHeader, Object> runtime =
		    (JFieldRuntime<JHeader, Object>) field.getRuntime();

		incLevel(PAD);

		if (field.getStyle() == Style.BYTE_ARRAY_HEX_DUMP) {
			pad().format(LT + "hexdump offset=\"%d\" length=\"%d\"" + GT,
			    runtime.getOffset(header), runtime.getLength(header));
			incLevel(PAD);

			final String[] v =
			    stylizeMultiLine(header, field, Style.BYTE_ARRAY_HEX_DUMP_NO_TEXT,
			        runtime.value(header));

			incLevel(PAD);
			for (String i : v) {
				pad().format(LT + "hexline data=\"%s\"/" + GT, i.trim());
			}

			decLevel();

		} else if (false && field.hasSubFields()) {
			final String v = stylizeSingleLine(header, field, runtime.value(header));

			pad().format(
			    LT + "field name=\"%s\" value=\"%s\" offset=\"%d\" length=\"%d\""
			        + GT, field.getName(), v, runtime.getOffset(header),
			    runtime.getLength(header));

		} else if (field.getStyle() == Style.INT_BITS) {
		} else {
			final String v = stylizeSingleLine(header, field, runtime.value(header));

			pad().format(
			    LT + "field name=\"%s\" value=\"%s\" offset=\"%d\" length=\"%d\"/"
			        + GT, field.getName(), v, runtime.getOffset(header),
			    runtime.getLength(header));
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#end(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void headerAfter(JHeader header, Detail detail) throws IOException {

		pad().format(LT + "/header" + GT);
		pad();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#start(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void headerBefore(JHeader header, Detail detail) throws IOException {
		pad().format(LT + "header name=\"%s\"", header.getName());
		incLevel(PAD + PAD);

		pad().format("nicname=\"%s\"", header.getNicname());
		pad().format("classname=\"%s\"", header.getClass().getCanonicalName());
		pad().format("offset=\"%d\"", header.getOffset());
		pad().format("length=\"%d\"" + GT, header.getLength());
		decLevel();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#packetAfter(org.jnetpcap.packet.JPacket,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	public void packetAfter(JPacket packet, Detail detail) throws IOException {

		decLevel();
		pad().format(LT + "/packet" + GT);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#packetBefore(org.jnetpcap.packet.JPacket,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	public void packetBefore(JPacket packet, Detail detail) throws IOException {
		pad().format(LT + "packet len=\"%d\"", packet.size());
		incLevel(PAD + PAD);
		if (frameIndex != -1) {
			pad().format("index=\"%d\"", frameIndex);
		}

		pad().format("captureSeconds=\"%s\"", "Not Implemented");
		pad().format("captureNanoSeconds=\"%s\"" + GT, "Not Implemented");
		pad();
		decLevel();

		incLevel(PAD);
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

		headerAfter(subHeader, detail);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#subHeaderBefore(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void subHeaderBefore(JHeader header, JHeader subHeader,
	    Detail detail) throws IOException {
		headerBefore(subHeader, detail);
	}

}
