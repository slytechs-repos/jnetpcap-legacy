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

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;

/**
 * Various jUnit support utilities
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class TestUtils {

	private static JScanner scanner = new JScanner();

	/**
	 * Scans a packet that has been initialized but not scanned. Assumes ethernet
	 * is the DLT protocol
	 * 
	 * @param packet
	 *          packet to scan
	 * @return offset into the packet
	 */
	public static int scanPacket(JPacket packet) {
		return scanPacket(packet, JProtocol.ETHERNET_ID);
	}

	/**
	 * Scans a packet that has been initialized but not scanned.
	 * 
	 * @param packet
	 *          packet to scan
	 * @param id
	 *          id of the DLT protocol
	 * @return offset into the packet
	 */
	public static int scanPacket(JPacket packet, int id) {

		return scanner.scan(packet, id);
	}

	/**
	 * Retrieves a specific single packet from a file
	 * 
	 * @param file
	 *          capture file containing our packet
	 * @param index
	 *          0 based index of the packet to get
	 * @return the requested packet
	 */
	public static PcapPacket getPcapPacket(final String file, final int index) {

		/***************************************************************************
		 * First, open offline file
		 **************************************************************************/
		StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline(file, errbuf);
		if (pcap == null) {
			System.err.println(errbuf.toString());
			return null;
		}

		/***************************************************************************
		 * Second, setup a packet we're going to copy the captured contents into.
		 * Allocate 2K native memory block to hold both state and buffer. Notice
		 * that the packet has to be marked "final" in order for the JPacketHandler
		 * to be able to access that variable from within the loop.
		 **************************************************************************/
		final PcapPacket result = new PcapPacket(2 * 1024);

		/***************************************************************************
		 * Third, Enter our loop and count packets until we reach the index of the
		 * packet we are looking for.
		 **************************************************************************/
		pcap.loop(Pcap.LOOP_INFINATE, new JBufferHandler<Pcap>() {
			int i = 0;

			public void nextPacket(PcapHeader header, JBuffer buffer, Pcap pcap) {

				/***********************************************************************
				 * Forth, once we reach our packet transfer the capture data from our
				 * temporary, shared packet, to our preallocated permanent packet. The
				 * method transferStateAndDataTo will do a deep copy of the packet
				 * contents and state to the destination packet. The copy is done
				 * natively with memcpy. The packet content in destination packet is
				 * layout in memory as follows. At the front of the buffer is the
				 * packet_state_t structure followed immediately by the packet data
				 * buffer and its size is adjusted to the exact size of the temporary
				 * buffer. The remainder of the allocated memory block is unused, but
				 * needed to be allocated large enough to hold a decent size packet. To
				 * break out of the Pcap.loop we call Pcap.breakLoop().
				 **********************************************************************/
				if (i++ == index) {
					PcapPacket packet = new PcapPacket(header, buffer);
					packet.scan(JProtocol.ETHERNET_ID);
					
					packet.transferStateAndDataTo(result);

					pcap.breakloop();
					return;
				}
			}

		}, pcap);

		/***************************************************************************
		 * Lastly, we close the pcap handle and return our result :)
		 **************************************************************************/
		pcap.close();

		return result;
	}

	/**
	 * Opens up a pcap handle to specific file
   * @param fname
   */
  public static Pcap openOffline(String fname) {
		/***************************************************************************
		 * First, open offline file
		 **************************************************************************/
		StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline(fname, errbuf);
		if (pcap == null) {
			System.err.println(errbuf.toString());
			return null;
		}
		
	  return pcap;
  }

}
