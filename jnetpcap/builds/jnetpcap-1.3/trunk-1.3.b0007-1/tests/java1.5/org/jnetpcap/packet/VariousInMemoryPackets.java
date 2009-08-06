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
package org.jnetpcap.packet;

import org.jnetpcap.packet.format.FormatUtils;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class VariousInMemoryPackets {

	/**
	 * <pre>
	 * Ethernet:  ******* Ethernet (Eth) offset=0 length=14
	 * 	Ethernet: 
	 * 	Ethernet:      destination = 00-07-E9-14-78-A2
	 * 	Ethernet:           source = 00-10-7B-81-24-45
	 * 	Ethernet:         protocol = 0x800 (2048)
	 * 	Ethernet: 
	 * 	ip4:  ******* ip4 (ip) offset=14 length=20
	 * 	ip4: 
	 * 	ip4:          version = 4
	 * 	ip4:             hlen = 5 [*4 = 20 bytes]
	 * 	ip4:            diffs = 0xC0 (192)
	 * 	ip4:                    1100 00..  = [48] reserved bit: code point 48
	 * 	ip4:                    .... ..0.  = [0] ECN bit: ECN capable transport: no
	 * 	ip4:                    .... ...0  = [0] ECE bit: ECE-CE: no
	 * 	ip4:           length = 40
	 * 	ip4:            flags = 0x0 (0)
	 * 	ip4:                    0..  = [0] reserved bit: not set
	 * 	ip4:                    .0.  = [0] don't fragment: not set
	 * 	ip4:                    ..0  = [0] more fragments: not set
	 * 	ip4:               id = 0x5 (5)
	 * 	ip4:           offset = 0
	 * 	ip4:     time to live = 255 router hops
	 * 	ip4:         protocol = 17
	 * 	ip4:  header checksum = 0x70E7 (28903)
	 * 	ip4:           source = 192.168.98.222
	 * 	ip4:      destination = 192.168.101.233
	 * 	ip4: 
	 * 	udp:  ******* udp (udp) offset=34 length=8
	 * 	udp: 
	 * 	udp:           source = 1701
	 * 	udp:      destination = 1701
	 * 	udp:           length = 20
	 * 	udp:         checksum = 57418
	 * 	udp: 
	 * 	l2tp:  ******* l2tp (l2tp) offset=42 length=12
	 * 	l2tp: 
	 * 	l2tp:            flags = 0xC802 (51202)
	 * 	l2tp:                    1... .... .... ....  = [1] type bit: control message
	 * 	l2tp:                    .1.. .... .... ....  = [1] length bit: length field is present
	 * 	l2tp:                    .... 1... .... ....  = [1] sequence bit: Ns and Nr fields are present
	 * 	l2tp:                    .... ..0. .... ....  = [0] offset bit: offset size field is not present
	 * 	l2tp:                    .... ...0 .... ....  = [0] priority bit: no priority
	 * 	l2tp:                    .... .... .... 0010  = [2] version: version is 2
	 * 	l2tp:          version = 2
	 * 	l2tp:           length = 12
	 * 	l2tp:         tunnelId = 2
	 * 	l2tp:        sessionId = 0
	 * 	l2tp:               ns = 2
	 * 	l2tp:               nr = 6
	 * 	l2tp: 
	 * 	payload:  ******* payload (data) offset=54 length=10
	 * 	payload: 
	 * 	payload: 0036: 00000000 00000000 0000                \0 \0 \0 \0 \0 \0 \0 \0 \0 \0       
	 * 	payload: 
	 * </pre>
	 */
	public final static byte[] PACKET_1 =
		FormatUtils.toByteArray("" + "0007e914 78a20010 7b812445 080045c0"
	        + "00280005 0000ff11 70e7c0a8 62dec0a8"
	        + "65e906a5 06a50014 e04ac802 000c0002"
	        + "00000002 00060000 00000000");

}
