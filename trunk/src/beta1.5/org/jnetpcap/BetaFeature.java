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

import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JProtocol;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;

/**
 * Adds new features to jNetPcap API. This class is made up of static methods
 * that extend the capabilities of Pcap class. The new methods and features are
 * provided but are not part of the larger production API.
 * <p>
 * The class adds several <code>dispatch</code> and <code>loop</code>
 * methods that take a new class <code>JPacketHandler</code> as a parameter.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class BetaFeature {

	/**
	 * <p>
	 * Collect a group of packets. pcap_dispatch() is used to collect and process
	 * packets. cnt specifies the maximum number of packets to process before
	 * returning. This is not a minimum number; when reading a live capture, only
	 * one bufferful of packets is read at a time, so fewer than cnt packets may
	 * be processed. A cnt of -1 processes all the packets received in one buffer
	 * when reading a live capture, or all the packets in the file when reading a
	 * ``savefile''. callback specifies a routine to be called with three
	 * arguments: a u_char pointer which is passed in from pcap_dispatch(), a
	 * const struct pcap_pkthdr pointer, and a const u_char pointer to the first
	 * caplen (as given in the struct pcap_pkthdr a pointer to which is passed to
	 * the callback routine) bytes of data from the packet (which won't
	 * necessarily be the entire packet; to capture the entire packet, you will
	 * have to provide a value for snaplen in your call to pcap_open_live() that
	 * is sufficiently large to get all of the packet's data - a value of 65535
	 * should be sufficient on most if not all networks).
	 * </p>
	 * <p>
	 * The number of packets read is returned. 0 is returned if no packets were
	 * read from a live capture (if, for example, they were discarded because they
	 * didn't pass the packet filter, or if, on platforms that support a read
	 * timeout that starts before any packets arrive, the timeout expires before
	 * any packets arrive, or if the file descriptor for the capture device is in
	 * non-blocking mode and no packets were available to be read) or if no more
	 * packets are available in a ``savefile.'' A return of -1 indicates an error
	 * in which case pcap_perror() or pcap_geterr() may be used to display the
	 * error text. A return of -2 indicates that the loop terminated due to a call
	 * to pcap_breakloop() before any packets were processed. If your application
	 * uses pcap_breakloop(), make sure that you explicitly check for -1 and -2,
	 * rather than just checking for a return value < 0.
	 * </p>
	 * <p>
	 * Note: when reading a live capture, pcap_dispatch() will not necessarily
	 * return when the read times out; on some platforms, the read timeout isn't
	 * supported, and, on other platforms, the timer doesn't start until at least
	 * one packet arrives. This means that the read timeout should NOT be used in,
	 * for example, an interactive application, to allow the packet capture loop
	 * to ``poll'' for user input periodically, as there's no guarantee that
	 * pcap_dispatch() will return after the timeout expires.
	 * </p>
	 * <p>
	 * This implementation of disptach method performs a scan of the packet buffer
	 * as it is delivered by libpcap. The scanned information is recorded in
	 * native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer than
	 * a single iteration of the dispatcher, the delivered packets state must
	 * either be peered with a different packet (only copied by reference) or the
	 * entire contents and state must be copied to a new packet (a deep copy). The
	 * shallow copy by reference persists longer, but not indefinately. It persist
	 * as long as libpcap internal large capture buffer doesn't wrap around. The
	 * same goes for JScanner's internal scan buffer, it too persists until the
	 * state information exhausts the buffer and the buffer is wrapped around to
	 * the begining as well overriding any information in the scan buffer. If
	 * there are still any packets that reference that scan buffer information,
	 * once that information is overriden by the latest scan, the original scan
	 * information is gone forever and will guarrantee that any old packets still
	 * pointing at the scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * 
	 * @param <T>
	 *          user data type
	 * @param pcap
	 *          open pcap handle
	 * @param cnt
	 *          number of packets to process
	 * @param id
	 *          numerical protocol ID found in JProtocol.ID constant and in
	 *          JRegistery
	 * @param handler
	 *          user supplied packet handler
	 * @param user
	 *          a custom opaque user object
	 * @return number of packet captured
	 */
	public static <T> int dispatch(Pcap pcap, int cnt, int id,
	    JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(pcap, cnt, id, handler, user, packet, packet.getState(),
		    packet.getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Private native implemenation.
	 * 
	 * @param <T>
	 * @param pcap
	 * @param cnt
	 * @param id
	 * @param handler
	 * @param user
	 * @param packet
	 * @param state
	 * @param header
	 * @param scanner
	 * @return
	 */
	private static native <T> int dispatch(Pcap pcap, int cnt, int id,
	    JPacketHandler<T> handler, T user, JPacket packet, JPacket.State state,
	    PcapHeader header, JScanner scanner);

	/**
	 * <p>
	 * Collect a group of packets. pcap_dispatch() is used to collect and process
	 * packets. cnt specifies the maximum number of packets to process before
	 * returning. This is not a minimum number; when reading a live capture, only
	 * one bufferful of packets is read at a time, so fewer than cnt packets may
	 * be processed. A cnt of -1 processes all the packets received in one buffer
	 * when reading a live capture, or all the packets in the file when reading a
	 * ``savefile''. callback specifies a routine to be called with three
	 * arguments: a u_char pointer which is passed in from pcap_dispatch(), a
	 * const struct pcap_pkthdr pointer, and a const u_char pointer to the first
	 * caplen (as given in the struct pcap_pkthdr a pointer to which is passed to
	 * the callback routine) bytes of data from the packet (which won't
	 * necessarily be the entire packet; to capture the entire packet, you will
	 * have to provide a value for snaplen in your call to pcap_open_live() that
	 * is sufficiently large to get all of the packet's data - a value of 65535
	 * should be sufficient on most if not all networks).
	 * </p>
	 * <p>
	 * The number of packets read is returned. 0 is returned if no packets were
	 * read from a live capture (if, for example, they were discarded because they
	 * didn't pass the packet filter, or if, on platforms that support a read
	 * timeout that starts before any packets arrive, the timeout expires before
	 * any packets arrive, or if the file descriptor for the capture device is in
	 * non-blocking mode and no packets were available to be read) or if no more
	 * packets are available in a ``savefile.'' A return of -1 indicates an error
	 * in which case pcap_perror() or pcap_geterr() may be used to display the
	 * error text. A return of -2 indicates that the loop terminated due to a call
	 * to pcap_breakloop() before any packets were processed. If your application
	 * uses pcap_breakloop(), make sure that you explicitly check for -1 and -2,
	 * rather than just checking for a return value < 0.
	 * </p>
	 * <p>
	 * Note: when reading a live capture, pcap_dispatch() will not necessarily
	 * return when the read times out; on some platforms, the read timeout isn't
	 * supported, and, on other platforms, the timer doesn't start until at least
	 * one packet arrives. This means that the read timeout should NOT be used in,
	 * for example, an interactive application, to allow the packet capture loop
	 * to ``poll'' for user input periodically, as there's no guarantee that
	 * pcap_dispatch() will return after the timeout expires.
	 * </p>
	 * <p>
	 * This implementation of disptach method performs a scan of the packet buffer
	 * as it is delivered by libpcap. The scanned information is recorded in
	 * native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer than
	 * a single iteration of the dispatcher, the delivered packets state must
	 * either be peered with a different packet (only copied by reference) or the
	 * entire contents and state must be copied to a new packet (a deep copy). The
	 * shallow copy by reference persists longer, but not indefinately. It persist
	 * as long as libpcap internal large capture buffer doesn't wrap around. The
	 * same goes for JScanner's internal scan buffer, it too persists until the
	 * state information exhausts the buffer and the buffer is wrapped around to
	 * the begining as well overriding any information in the scan buffer. If
	 * there are still any packets that reference that scan buffer information,
	 * once that information is overriden by the latest scan, the original scan
	 * information is gone forever and will guarrantee that any old packets still
	 * pointing at the scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * <p>
	 * This method derrives the numerical protocol ID for the data link header
	 * automatically using <code>Pcap.datalink()</code> value returned.
	 * </p>
	 * 
	 * @param <T>
	 *          user data type
	 * @param pcap
	 *          open pcap handle
	 * @param cnt
	 *          number of packets to process
	 * @param handler
	 *          user supplied packet handler
	 * @param user
	 *          a custom opaque user object
	 * @return number of packet captured
	 */
	public static <T> int dispatch(Pcap pcap, int cnt, JPacketHandler<T> handler,
	    T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(pcap, cnt, JProtocol.id(pcap), handler, user, packet, packet
		    .getState(), packet.getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an error
	 * occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error; 0
	 * is returned if cnt is exhausted; -2 is returned if the loop terminated due
	 * to a call to pcap_breakloop() before any packets were processed. If your
	 * application uses pcap_breakloop(), make sure that you explicitly check for
	 * -1 and -2, rather than just checking for a return value < 0.
	 * <p>
	 * This implementation of disptach method performs a scan of the packet buffer
	 * as it is delivered by libpcap. The scanned information is recorded in
	 * native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer than
	 * a single iteration of the dispatcher, the delivered packets state must
	 * either be peered with a different packet (only copied by reference) or the
	 * entire contents and state must be copied to a new packet (a deep copy). The
	 * shallow copy by reference persists longer, but not indefinately. It persist
	 * as long as libpcap internal large capture buffer doesn't wrap around. The
	 * same goes for JScanner's internal scan buffer, it too persists until the
	 * state information exhausts the buffer and the buffer is wrapped around to
	 * the begining as well overriding any information in the scan buffer. If
	 * there are still any packets that reference that scan buffer information,
	 * once that information is overriden by the latest scan, the original scan
	 * information is gone forever and will guarrantee that any old packets still
	 * pointing at the scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * <p>
	 * This method derrives the numerical protocol ID for the data link header
	 * automatically using <code>Pcap.datalink()</code> value returned.
	 * </p>
	 * 
	 * @param <T>
	 *          user data type
	 * @param pcap
	 *          open pcap handle
	 * @param cnt
	 *          number of packets to process
	 * @param id
	 *          numerical protocol ID found in JProtocol.ID constant and in
	 *          JRegistery
	 * @param handler
	 *          user supplied packet handler
	 * @param user
	 *          a custom opaque user object
	 * @return number of packet captured
	 */
	public static <T> int loop(Pcap pcap, int cnt, int id,
	    JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(pcap, cnt, id, handler, user, packet, packet.getState(), packet
		    .getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Private native implementation
	 * 
	 * @param <T>
	 * @param pcap
	 * @param cnt
	 * @param id
	 * @param handler
	 * @param user
	 * @param packet
	 * @param state
	 * @param header
	 * @param scanner
	 * @return
	 */
	private static native <T> int loop(Pcap pcap, int cnt, int id,
	    JPacketHandler<T> handler, T user, JPacket packet, JPacket.State state,
	    PcapHeader header, JScanner scanner);

	/**
	 * Collect a group of packets. pcap_loop() is similar to pcap_dispatch()
	 * except it keeps reading packets until cnt packets are processed or an error
	 * occurs. It does not return when live read timeouts occur. Rather,
	 * specifying a non-zero read timeout to pcap_open_live() and then calling
	 * pcap_dispatch() allows the reception and processing of any packets that
	 * arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop
	 * forever (or at least until an error occurs). -1 is returned on an error; 0
	 * is returned if cnt is exhausted; -2 is returned if the loop terminated due
	 * to a call to pcap_breakloop() before any packets were processed. If your
	 * application uses pcap_breakloop(), make sure that you explicitly check for
	 * -1 and -2, rather than just checking for a return value < 0.
	 * <p>
	 * This implementation of disptach method performs a scan of the packet buffer
	 * as it is delivered by libpcap. The scanned information is recorded in
	 * native scanner structures which are then peered with a JPacket object
	 * instance. The receiver of the dispatched packets
	 * <code>JPacketHandler.nextPacket</code> receives fully decoded packets.
	 * </p>
	 * <p>
	 * This method provides its own thread-local <code>JScanner</code> and
	 * default shared <code>JPacket</code> instance. The same packet is
	 * dispatched to the user with the state of the packet being changed between
	 * each dispatch. If the user requires the packet state to persist longer than
	 * a single iteration of the dispatcher, the delivered packets state must
	 * either be peered with a different packet (only copied by reference) or the
	 * entire contents and state must be copied to a new packet (a deep copy). The
	 * shallow copy by reference persists longer, but not indefinately. It persist
	 * as long as libpcap internal large capture buffer doesn't wrap around. The
	 * same goes for JScanner's internal scan buffer, it too persists until the
	 * state information exhausts the buffer and the buffer is wrapped around to
	 * the begining as well overriding any information in the scan buffer. If
	 * there are still any packets that reference that scan buffer information,
	 * once that information is overriden by the latest scan, the original scan
	 * information is gone forever and will guarrantee that any old packets still
	 * pointing at the scan buffer will have incorrect infromation.
	 * </p>
	 * <p>
	 * <code>JPacket</code> class provides methods which allow deep copy of the
	 * packet data and state to be made to a new permanent location. This
	 * mechanism works in conjuction of <code>JMemoryPool</code> class which
	 * facilitates native memory management on large scale. Once the packet data
	 * and state are deep copied to new memory location, that packet can stay
	 * permanently in memory. The memory will only be released when all the java
	 * object references to that memory are garbage collected. The memory is
	 * deallocated automatically.
	 * </p>
	 * 
	 * @param <T>
	 *          user data type
	 * @param pcap
	 *          open pcap handle
	 * @param cnt
	 *          number of packets to process
	 * @param handler
	 *          user supplied packet handler
	 * @param user
	 *          a custom opaque user object
	 * @return number of packet captured
	 */
	public static <T> int loop(Pcap pcap, int cnt, JPacketHandler<T> handler,
	    T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(pcap, cnt, JProtocol.id(pcap), handler, user, packet, packet
		    .getState(), packet.getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * 
	 */
	private BetaFeature() {
		// Empty
	}
}
