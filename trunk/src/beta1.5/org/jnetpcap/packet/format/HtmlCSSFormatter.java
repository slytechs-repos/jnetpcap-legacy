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
public class HtmlCSSFormatter
    extends JFormatter {

	private static final String PAD = "  ";

	private static final String LT = "<";

	private static final String GT = ">";

	/**
	 * 
	 */
	public HtmlCSSFormatter() {
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
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#fieldBefore(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JField,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void fieldBefore(JHeader header, JField field, Detail detail)
	    throws IOException {
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#headerAfter(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void headerAfter(JHeader header, Detail detail) throws IOException {
		
		decLevel();
		
		pad().format(LT + "/div" + GT);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#headerBefore(org.jnetpcap.packet.JHeader,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	protected void headerBefore(JHeader header, Detail detail) throws IOException {
		pad().format(LT + "div class=\"cl_header cl_header_%s\" id=\"id_header_%d_%s\"" + GT,
		    header.getName(), frameIndex, header.getName());
		
		incLevel(PAD);

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

		pad().format(LT + "/div" + GT);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.format.JFormatter#packetBefore(org.jnetpcap.packet.JPacket,
	 *      org.jnetpcap.packet.format.JFormatter.Detail)
	 */
	@Override
	public void packetBefore(JPacket packet, Detail detail) throws IOException {

		pad().format(LT + "div class=\"cl_packet\" id=\"id_packet_%d\"" + GT,
		    frameIndex);

		incLevel(PAD);
	}

}
