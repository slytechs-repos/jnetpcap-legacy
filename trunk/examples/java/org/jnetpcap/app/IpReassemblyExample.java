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
package org.jnetpcap.app;

import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.header.Ip4;

/**
 * This is a demonstration application for reassembling IP fragments. The
 * application is intended only for show purposes on how jNetPcap API can be
 * used.
 * <p>
 * This example application captures IP packets, makes sure they are IPs and
 * creates special packets that are ip only. We will use JMemoryPacket which
 * nicely allows us to construct a new custom packet. Our new packets don't care
 * about the lower OSI layers since that information is irrelavent for Ip
 * reassembly and for the user as well. If we receive a packet that is not
 * fragmented we simply pass it through, no sense in doing anything special with
 * it.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class IpReassemblyExample implements PcapPacketHandler<Object> {

	/**
	 * Our custom interface that allows listeners to get our special reassembled
	 * IP packets and also provide them with the actual reassembled buffer. The
	 * reassembly buffer provides information about any holes in the buffer which
	 * is important when packets are incomplete.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 * @param <T>
	 */
	public interface IpPacketHandler {
		public void nextIpDatagram(IpReassemblyBuffer buffer);
	}

	/**
	 * A special buffer that keeps track of ip fragment holes in it
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class IpReassemblyBuffer
	    extends JBuffer implements Comparable<IpReassemblyBuffer> {

		/**
		 * A flag that keeps track of we already have received the last fragment but
		 * still have holes in other parts of the datagram
		 */
		private boolean hasLast = false;

		private Ip4 header = new Ip4();

		/**
		 * Current length of the reassembled IP fragments
		 */
		private int last = -1;

		private int length = 20;

		private final int start = 20; // length Ip4 header

		private final long timeout;

		private final int hash;

		@Override
		public int hashCode() {
			return this.hash;
		}

		/**
		 * @param size
		 */
		public IpReassemblyBuffer(Ip4 ip, int size, long timeout, int hash) {
			super(size);
			this.timeout = timeout;
			this.hash = hash;

			transferFrom(ip);

		}

		private void transferFrom(Ip4 ip) {
			/*
			 * Copy ip header as a template
			 */
			ip.transferTo(this, 0, 20, 0);

			/*
			 * Peer a temporary working Ip4 header to the start of our buffer. It
			 * contains our template Ip4 header data.
			 */
			header.peer(this, 0, 20);

			/*
			 * Now reset a few things that are no longer neccessary in a reassembled
			 * datagram
			 */
			header.hlen(5); // Clear IP optional headers
			header.clearFlags(Ip4.FLAG_MORE_FRAGEMNTS); // FRAG flag
			header.offset(0); // Offset is now 0
			header.checksum(0); // Reset header CRC, unless we calculate it again
		}

		public void addLastSegment(JBuffer packet, int offset, int length,
		    int packetOffset) {

			addSegment(packet, offset, length, packetOffset);

			/*
			 * Trucate the size of the JBuffer to match that of ip reassebly buffer
			 * now that we know that we have received the last fragment and where it
			 * ends
			 */
			super.setSize(offset + length);
			this.hasLast = true;
			this.last = start + offset + length;

			/*
			 * Set Ip4 total length field, now that we know what it is
			 */
			header.length(offset + length); // Set Ip4 total length field
		}

		public void addSegment(JBuffer packet, int offset, int length,
		    int packetOffset) {

			this.length += length;

			packet.transferTo(this, packetOffset, length, offset + start);
		}

		/**
		 * For ordering buffers according to their timeout value
		 */
		public int compareTo(IpReassemblyBuffer o) {
			return (int) (o.timeout - this.timeout);
		}

		public boolean hasHole() {
			return this.last == this.length;
		}

		public final boolean hasLast() {
			return this.hasLast;
		}

		public boolean isComplete() {
			return this.last == this.length && hasLast == true;
		}

		public boolean isTimedout() {
			return this.timeout < System.currentTimeMillis();
		}

		/**
		 * @return
		 */
		public Ip4 getIpHeader() {
			return header;
		}

	}

	private static final int DEFAULT_REASSEMBLY_SIZE = 8 * 1024; // 8k packets

	public static void main(String[] args) {

		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline("tests/test-ipreassembly2.pcap", errbuf);
		if (pcap == null) {
			System.err.println(errbuf.toString());
			return;
		}

		pcap.loop(6, new IpReassemblyExample(5 * 1000, new IpPacketHandler() {

			public void nextIpDatagram(IpReassemblyBuffer buffer) {

				if (buffer.isComplete() == false) {
					System.err.println("WARNING: missing fragments");
				} else {
					JPacket packet = new JMemoryPacket(Type.POINTER);
					packet.peer(buffer);
					packet.scan(Ip4.ID); // decode the packet

					System.out.println(packet.toString());
				}

			}

		}), null);
	}

	/**
	 * Keeps track of all IP datagrams being reassembled
	 */
	private Map<Integer, IpReassemblyBuffer> buffers =
	    new HashMap<Integer, IpReassemblyBuffer>();

	private IpPacketHandler handler;

	private Ip4 ip = new Ip4(); // Ip4 header

	private final long timeout;

	private final Queue<IpReassemblyBuffer> timeoutQueue =
	    new PriorityQueue<IpReassemblyBuffer>();

	/**
	 * @param timeout
	 * @param handler
	 * @param userData
	 */
	public IpReassemblyExample(long timeout, IpPacketHandler handler) {
		this.timeout = timeout;
		if (handler == null) {
			throw new NullPointerException();
		}
		this.handler = handler;
	}

	/**
	 * @param packet
	 * @param ip
	 */
	private IpReassemblyBuffer bufferFragment(PcapPacket packet, Ip4 ip) {
		IpReassemblyBuffer buffer = getBuffer(ip);

		/*
		 * Lets keep in mind that ip.getOffset() is a header offset into the packet
		 * buffer, while ip.offset() is the Ip4.offset field which is the fragment
		 * offset into the overall datagram, in multiples of 8 bytes
		 */
		final int hlen = ip.hlen() * 4;
		final int len = ip.length() - hlen;
		final int packetOffset = ip.getOffset() + hlen;
		final int dgramOffset = ip.offset() * 8;
		buffer.addSegment(packet, dgramOffset, len, packetOffset);

		if (buffer.isComplete()) {
			if (buffers.remove(ip.hashCode()) == null) {
				System.err.println("bufferFragment(): failed to remove buffer");
				System.exit(0);
			}
			timeoutQueue.remove(buffer);

			dispatch(buffer);
		}

		return buffer;
	}

	/**
	 * @param packet
	 * @param ip
	 */
	private IpReassemblyBuffer bufferLastFragment(PcapPacket packet, Ip4 ip) {
		IpReassemblyBuffer buffer = getBuffer(ip);

		/*
		 * Lets keep in mind that ip.getOffset() is a header offset into the packet
		 * buffer, while ip.offset() is the Ip4.offset field which is the fragment
		 * offset into the overall datagram, in multiples of 8 bytes
		 */
		final int hlen = ip.hlen() * 4;
		final int len = ip.length() - hlen;
		final int packetOffset = ip.getOffset() + hlen;
		final int dgramOffset = ip.offset() * 8;
		buffer.addLastSegment(packet, dgramOffset, len, packetOffset);

		if (buffer.isComplete()) {
			if (buffers.remove(buffer.hashCode()) == null) {
				System.err.println("bufferLastFragment(): failed to remove buffer");
				System.exit(0);
			}
			timeoutQueue.remove(buffer);

			dispatch(buffer);
		}

		return buffer;
	}

	/**
	 * @param packet
	 * @param ip
	 */
	private void dispatch(IpReassemblyBuffer buffer) {
		handler.nextIpDatagram(buffer);
	}

	private IpReassemblyBuffer getBuffer(Ip4 ip) {
		/*
		 * We create a hash of ip.id, ip.saddr, ip.daddr, ip.proto. Instead of
		 * reading ip4 addresses as byte arrays, for our purpose we're going to read
		 * them as int (32 bits) so we can perform our hash easier. We don't care
		 * about the sign so just plain old java ints.
		 */
		final int src = ip.sourceToInt(); // Ip4 source address
		final int dst = ip.destinationToInt(); // ip4 destination address
		final int hash = (ip.id() << 16) ^ src ^ dst ^ ip.type();

		IpReassemblyBuffer buffer = buffers.get(hash);
		if (buffer == null) { // First time we're seeing this id

			/*
			 * Calculate when the buffer should be timedout due to missing fragments
			 */
			final long bufTimeout = System.currentTimeMillis() + this.timeout;
			buffer =
			    new IpReassemblyBuffer(ip, DEFAULT_REASSEMBLY_SIZE, bufTimeout, hash);
			buffers.put(hash, buffer);
		}

		return buffer;
	}

	/**
	 * Catch incoming packets from libpcap
	 * 
	 * @param packet
	 *          a temporary singleton packet received from libpcap
	 * @param user
	 *          user object
	 */
	public void nextPacket(PcapPacket packet, Object user) {

		if (packet.hasHeader(ip)) {
			final int flags = ip.flags();

			/*
			 * Check if we have an IP fragment
			 */
			if ((flags & Ip4.FLAG_MORE_FRAGEMNTS) != 0) {
				bufferFragment(packet, ip);

				/*
				 * record the last fragment
				 */
			} else {

				bufferLastFragment(packet, ip);

				/*
				 * Here we have a non-fragmented IP packet so we just pass it on
				 */
			}

			/*
			 * Our crude timeout mechanism, should be implemented as a separate thread
			 */
			timeoutBuffers();
		}
	}

	/**
	 * 
	 */
	private void timeoutBuffers() {
		while (timeoutQueue.isEmpty() == false) {

			if (timeoutQueue.peek().isTimedout()) {
				dispatch(timeoutQueue.poll());
			} else {
				break;
			}

		}
	}

}
