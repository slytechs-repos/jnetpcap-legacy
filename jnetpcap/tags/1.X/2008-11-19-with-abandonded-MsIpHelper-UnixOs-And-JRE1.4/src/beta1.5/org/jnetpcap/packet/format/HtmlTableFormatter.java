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

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class HtmlTableFormatter
    extends JFormatter {

	private static final String PAD = "  ";

	private static final String LT = "&lt;";

	private static final String GT = "&gt;";

	private static final String W = "border=\"2px\"";

	public HtmlTableFormatter(Appendable out) {
		setOutput(out);
	}

	/**
	 * 
	 */
	public HtmlTableFormatter() {
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#fieldAfter(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JField,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void fieldAfter(JHeader header, JField field, Detail detail)
	    throws IOException {

		decLevel();

		// pad().format(LT + "/td" + GT);
		// decLevel();

		pad().format(LT + "/tr" + GT);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#fieldBefore(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JField,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@SuppressWarnings("unchecked")
  @Override
	protected void fieldBefore(JHeader header, JField field, Detail detail)
	    throws IOException {

		final JFieldRuntime<JHeader, Object> runtime =
		    (JFieldRuntime<JHeader, Object>) field.getRuntime();

		if (field.getStyle() == Style.BYTE_ARRAY_HEX_DUMP) {

			final String[] a =
			    stylizeMultiLine(header, field, Style.BYTE_ARRAY_HEX_DUMP_ADDRESS,
			        runtime.value(header));

			final String[] d =
			    stylizeMultiLine(header, field,
			        Style.BYTE_ARRAY_HEX_DUMP_NO_TEXT_ADDRESS, runtime.value(header));

			final String[] t =
			    stylizeMultiLine(header, field, Style.BYTE_ARRAY_HEX_DUMP_TEXT,
			        runtime.value(header));

			incLevel(PAD);
			
			pad().format(
			    LT + "tr class=\"cl_field cl_field_%s\" id=\"id_field_%d_%s\"" + GT,
			    field.getName(), frameIndex, field.getName());
			incLevel(PAD);
			for (int i = 0; i < a.length; i++) {
				pad().format(
				    LT + "td class=\"cl_field cl_field_%s\" id=\"id_field_%d_%s\"" + GT,
				    field.getName(), frameIndex, field.getName());
				pad().format(a[i].trim());
				pad().format(LT + "/td" + GT);
				pad().format(LT + "td" + GT +"%s"+LT+"/td"+GT, d[i].trim());
				pad().format(LT + "td" + GT +"%s"+LT+"/td"+GT, t[i].trim());
			}
			decLevel();
			pad().format("</tr>");
		} else {
			pad().format(
			    LT + "tr class=\"cl_field cl_field_%s\" id=\"id_field_%d_%s\"" + GT,
			    field.getName(), frameIndex, field.getName());
			incLevel(PAD);

			final String v = stylizeSingleLine(header, field, runtime.value(header));
			pad()
			    .format(
			        LT + "td align=right"+GT+LT+"nobr"+GT+LT+"span class=cl_field_name cl_field_name_%s cl_style_%s>%s</span"+GT+LT+"/nobr"+GT+LT+"/td" + GT
			            + LT+"td"+GT+"="+LT+"/td"+GT
			            + LT+"td"+GT+LT+"nobr"+GT+LT+"span class=cl_field_value cl_field_value_%s"+GT+"%s"+LT+"/span"+GT+LT+"/nobr"+GT+LT+"/td"+GT,
			        field.getName(), field.getStyle().toString().toLowerCase(), field.getName(),
			        field.getName(), v);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#headerAfter(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void headerAfter(JHeader header, Detail detail) throws IOException {

		pad().format(LT + "/table" + GT);
		decLevel();

		pad().format(LT + "/td" + GT);
		decLevel();

		pad().format(LT + "/tr" + GT);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#headerBefore(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void headerBefore(JHeader header, Detail detail) throws IOException {
		pad().format(
		    LT + "tr class=\"cl_header cl_header_%s\" id=\"id_header_%d_%s\"" + GT,
		    header.getName(), frameIndex, header.getName());

		incLevel(PAD);
		pad().format(
		    LT + "td class=\"cl_header cl_header_%s\" id=\"id_header_%d_%s\"" + GT,
		    header.getName(), frameIndex, header.getName());

		incLevel(PAD);
		pad()
		    .format(
		        LT
		            + "table border=\"0px\" class=\"cl_header cl_header_%s\" id=\"id_header_%d_%s\""
		            + GT, header.getName(), frameIndex, header.getName());

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

		pad().format(LT + "/table" + GT);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#packetBefore(org.jnetpcap.packet.JPacket,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	public void packetBefore(JPacket packet, Detail detail) throws IOException {

		pad().format(
		    LT + "table " + W + " class=\"cl_packet\" id=\"id_packet_%d\"" + GT,
		    frameIndex);

		incLevel(PAD);
	}

}
