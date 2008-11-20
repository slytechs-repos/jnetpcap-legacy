/**
 * Copyright (C) 2008 Sly Technologies, Inc.
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
package org.jnetpcap;

import java.nio.ByteBuffer;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemoryPool;
import org.jnetpcap.nio.JStruct;
import org.jnetpcap.packet.JPacket;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 *
 */
public class PcapPacket
    extends JPacket {
	
	private PcapHeader captureHeader;

	/**
	 * 
	 */
	public PcapPacket() {
	}

	/**
	 * @param buffer
	 */
	public PcapPacket(ByteBuffer buffer) {
		super(buffer);
	}

	/**
	 * @param size
	 */
	public PcapPacket(int size) {
		super(size);
	}

	/**
	 * @param buffer
	 */
	public PcapPacket(JBuffer buffer) {
		super(buffer);
	}

	/**
	 * @param src
	 */
	public PcapPacket(JPacket src) {
		super(src);
	}

	/**
	 * @param src
	 * @param pool
	 */
	public PcapPacket(JPacket src, JMemoryPool pool) {
		super(src, pool);
	}

	/* (non-Javadoc)
   * @see org.jnetpcap.packet.JPacket#getCaptureHeader()
   */
  @Override
  public JCaptureHeader getCaptureHeader() {
	  return captureHeader;
  }

	/**
   * @param captureHeader the captureHeader to set
   */
  public final void setCaptureHeader(PcapHeader captureHeader) {
  	this.captureHeader = captureHeader;
  }
}
