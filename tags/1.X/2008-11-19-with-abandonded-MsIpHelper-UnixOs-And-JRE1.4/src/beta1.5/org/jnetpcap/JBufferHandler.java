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
package org.jnetpcap;

import org.jnetpcap.nio.JBuffer;




/**
 * This is a test interface with classes imbeded for a possible replacement to
 * loop and dispatch handers. These replacements are based on the JMemory class
 * and allow reuse of the allocated object to point pcap returned buffers in
 * memory. There are no plans to currently implement these, and they are checked
 * in simply as a way to allow a discussion and revision keeping on the entire
 * idea. JBufferHandler is the interface that dispatcher and loop would dispatch to.
 * JBuffer is a new type of buffer that can be reused on every packet instead of
 * ByteBuffer which must be allocated every time. Further more PcapHeader is
 * simply an extension to JBuffer which hard codes the structure of the
 * pcap_pkthdr structure into Java.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public interface JBufferHandler<T> {

	public void nextPacket(PcapHeader header, JBuffer buffer, T user);
}
