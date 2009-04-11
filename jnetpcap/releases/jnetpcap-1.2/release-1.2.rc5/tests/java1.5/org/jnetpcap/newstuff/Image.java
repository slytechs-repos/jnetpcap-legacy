/**
 * Copyright (C) 2009 Sly Technologies, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jnetpcap.newstuff;

import java.io.InputStream;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.util.SlidingBuffer;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
@Header
public class Image
    extends JHeader {
	
	@HeaderLength
	public static int headerLength(JBuffer buffer, int offset) {
		return buffer.size() - offset;
	}
	
	@Bind(to=Http.class)
	public static boolean bind2Http(JPacket packet, Http http) {
		Http.ContentType type = http.contentTypeEnum();
		if (type == Http.ContentType.JPEG) {
			return true;
		} else {
			return false;
		}
	}
	
	public enum Type {
		JPEG,
		GIF,
		BMP,
		SVG,
	}

	/**
   * @return
   */
  public Type type() {
	  // TODO Auto-generated method stub
	  throw new UnsupportedOperationException("Not implemented yet");
  }

	/**
   * @return
   */
  public int length() {
	  // TODO Auto-generated method stub
	  throw new UnsupportedOperationException("Not implemented yet");
  }

	/**
   * @return
   */
  public JBuffer getReassembledBuffer() {
	  // TODO Auto-generated method stub
	  throw new UnsupportedOperationException("Not implemented yet");
  }

	/**
   * @return
   */
  public JPacket getReassembledPacket() {
	  // TODO Auto-generated method stub
	  throw new UnsupportedOperationException("Not implemented yet");
  }

	/**
   * @return
   */
  public InputStream getInputStream() {
	  // TODO Auto-generated method stub
	  throw new UnsupportedOperationException("Not implemented yet");
  }

	/**
   * @return
   */
  public SlidingBuffer getSlidingBuffer() {
	  // TODO Auto-generated method stub
	  throw new UnsupportedOperationException("Not implemented yet");
  }

}
