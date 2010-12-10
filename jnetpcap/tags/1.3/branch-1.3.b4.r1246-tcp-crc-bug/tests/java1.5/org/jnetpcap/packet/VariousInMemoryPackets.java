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
package org.jnetpcap.packet;

import org.jnetpcap.packet.format.FormatUtils;

// TODO: Auto-generated Javadoc
/**
 * The Class VariousInMemoryPackets.
 */
public class VariousInMemoryPackets {

	/** The Constant PACKET_1. */
	public final static byte[] PACKET_1 =
	    FormatUtils.toByteArray("" + "0007e914 78a20010 7b812445 080045c0"
	        + "00280005 0000ff11 70e7c0a8 62dec0a8"
	        + "65e906a5 06a50014 e04ac802 000c0002"
	        + "00000002 00060000 00000000");

	/** The Constant PACKET_2. */
	public final static byte[] PACKET_2 =
	    FormatUtils.toByteArray(""
	        + "0007e914 78a20010 7b812445 0044" // 802.3 (len= frame)
	        + "aaaa03" // LLC
	        + "000000 0800" // SNAP
	        + "45c0" // IP4
	        + "00280005 0000ff11 70e7c0a8 62dec0a8"
	        + "65e906a5 06a50014 e04ac802 000c0002"
	        + "00000002 00060000 00000000");

	/** The Constant PACKET_2_TRAILER. */
	public final static byte[] PACKET_2_TRAILER =
	    FormatUtils.toByteArray(""
	        + "0007e914 78a20010 7b812445 0044" // 802.3 (len = frame + FCS)
	        + "aaaa03" // LLC
	        + "000000 0800" // SNAP
	        + "45c0" // IP4
	        + "00280005 0000ff11 70e7c0a8 62dec0a8"
	        + "65e906a5 06a50014 e04ac802 000c0002"
	        + "00000002 00060000 00000000" + "112233445566778899" // Ethernet FCS
	    );

}
