/**
 * Copyright (C) 2009 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.protocol.application;

import java.awt.Image;
import java.awt.Toolkit;
import java.io.InputStream;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JBufferInputStream;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.tcpip.Http;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header
public class WebImage
    extends
    JHeader {

	public enum Type {
		BMP,
		GIF,
		JPEG,
		SVG,
	}


	@Bind(to = Http.class)
	public static boolean bind2Http(JPacket packet, Http http) {
		Http.ContentType type = http.contentTypeEnum();
		switch (type) {
			case JPEG:
			case PNG:
			case GIF:
				return true;

			default:
				return false;
		}
	}

	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		return buffer.size() - offset;
	}

	private byte[] data;

	@Override
	protected void decodeHeader() {
		this.data = null; // Reinitialize
	}

	public Image getAWTImage() {
		if (data == null) {
			data = super.getByteArray(0, this.size());
		}
		return Toolkit.getDefaultToolkit().createImage(data);
	}

	/**
	 * @return
	 */
	public InputStream getInputStream() {
		return new JBufferInputStream(this);
	}

	/**
	 * @return
	 */
	public int length() {
		return this.size();
	}
}
