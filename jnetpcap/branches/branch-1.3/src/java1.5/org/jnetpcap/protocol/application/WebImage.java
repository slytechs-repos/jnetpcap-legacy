/*
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010 Sly Technologies, Inc.
 *
 * This file is part of jNetPcap.
 *
 * jNetPcap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation, either version 3 of 
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
