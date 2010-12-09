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
package org.jnetpcap;

import java.nio.ByteBuffer;
import java.util.List;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JNumber;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.JProtocol;

// TODO: Auto-generated Javadoc
/**
 * The Class Pcap.
 */
public class Pcap {

	/** The Constant DEFAULT_PROMISC. */
	public static final int DEFAULT_PROMISC = 1;

	/** The Constant DEFAULT_SNAPLEN. */
	public static final int DEFAULT_SNAPLEN = 64 * 1024;

	/** The Constant DEFAULT_TIMEOUT. */
	public static final int DEFAULT_TIMEOUT = 0;

	/** The Constant DISPATCH_BUFFER_FULL. */
	public static final int DISPATCH_BUFFER_FULL = -1;

	/** The Constant JNETPCAP_LIBRARY_NAME. */
	public static final String JNETPCAP_LIBRARY_NAME = "jnetpcap";

	/** The Constant LOOP_INFINATE. */
	public static final int LOOP_INFINATE = -1;

	/** The Constant LOOP_INTERRUPTED. */
	public static final int LOOP_INTERRUPTED = -2;

	/** The Constant MODE_BLOCKING. */
	public static final int MODE_BLOCKING = 0;

	/** The Constant MODE_NON_BLOCKING. */
	public static final int MODE_NON_BLOCKING = 1;

	/** The Constant MODE_NON_PROMISCUOUS. */
	public static final int MODE_NON_PROMISCUOUS = 0;

	/** The Constant MODE_PROMISCUOUS. */
	public static final int MODE_PROMISCUOUS = 1;

	/** The Constant NEXT_EX_EOF. */
	public static final int NEXT_EX_EOF = -2;

	/** The Constant NEXT_EX_NOT_OK. */
	public static final int NEXT_EX_NOT_OK = -1;

	/** The Constant NEXT_EX_OK. */
	public static final int NEXT_EX_OK = 1;

	/** The Constant NEXT_EX_TIMEDOUT. */
	public static final int NEXT_EX_TIMEDOUT = 0;

	/** The Constant NOT_OK. */
	public static final int NOT_OK = -1;

	/** The Constant OK. */
	public static final int OK = 0;

	/**
	 * Static initializer
	 */
	static {

		System.loadLibrary(JNETPCAP_LIBRARY_NAME);

		initIDs();

		try {
			// Make sure some classes that are needed get loaded too
			// we hold a Global reference to the class once initialized in JNI, will
			// never be unloaded
			Class.forName("org.jnetpcap.PcapDumper");
			Class.forName("org.jnetpcap.PcapIf");
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Compile no pcap.
	 * 
	 * @param snaplen
	 *          the snaplen
	 * @param dlt
	 *          the dlt
	 * @param program
	 *          the program
	 * @param str
	 *          the str
	 * @param optimize
	 *          the optimize
	 * @param netmask
	 *          the netmask
	 * @return the int
	 */
	public native static int compileNoPcap(
	    int snaplen,
	    int dlt,
	    PcapBpfProgram program,
	    String str,
	    int optimize,
	    int netmask);

	/**
	 * Datalink name to val.
	 * 
	 * @param name
	 *          the name
	 * @return the int
	 */
	public native static int datalinkNameToVal(String name);

	/**
	 * Datalink val to description.
	 * 
	 * @param dlt
	 *          the dlt
	 * @return the string
	 */
	public native static String datalinkValToDescription(int dlt);

	/**
	 * Datalink val to name.
	 * 
	 * @param dlt
	 *          the dlt
	 * @return the string
	 */
	public native static String datalinkValToName(int dlt);

	/**
	 * Find all devs.
	 * 
	 * @param alldevs
	 *          the alldevs
	 * @param errbuf
	 *          the errbuf
	 * @return the int
	 */
	public native static int findAllDevs(
	    List<PcapIf> alldevs,
	    StringBuilder errbuf);

	/**
	 * Free all devs.
	 * 
	 * @param alldevs
	 *          the alldevs
	 * @param errbuf
	 *          the errbuf
	 */
	public static void freeAllDevs(List<PcapIf> alldevs, byte[] errbuf) {
		// Empty do nothing method, java PcapIf objects currently have no link
		// to C structures and do not need to be freed up. All the C structures
		// used to building PcapIf chains are already free.
		if (alldevs == null || errbuf == null) {
			throw new NullPointerException();
		}

		alldevs.clear();
	}

	/**
	 * Free all devs.
	 * 
	 * @param alldevs
	 *          the alldevs
	 * @param errbuf
	 *          the errbuf
	 */
	public static void freeAllDevs(List<PcapIf> alldevs, StringBuilder errbuf) {
		// Empty do nothing method, java PcapIf objects currently have no link
		// to C structures and do not need to be freed up. All the C structures
		// used to building PcapIf chains are already free.
		if (alldevs == null || errbuf == null) {
			throw new NullPointerException();
		}
		errbuf.setLength(0);
		alldevs.clear();
	}

	/**
	 * Freecode.
	 * 
	 * @param program
	 *          the program
	 */
	public native static void freecode(PcapBpfProgram program);

	/**
	 * Inits the i ds.
	 */
	private native static void initIDs();

	/**
	 * Checks if is inject supported.
	 * 
	 * @return true, if is inject supported
	 */
	public native static boolean isInjectSupported();

	/**
	 * Checks if is send packet supported.
	 * 
	 * @return true, if is send packet supported
	 */
	public native static boolean isSendPacketSupported();

	/**
	 * Lib version.
	 * 
	 * @return the string
	 */
	public native static String libVersion();

	/**
	 * Lookup dev.
	 * 
	 * @param errbuf
	 *          the errbuf
	 * @return the string
	 */
	public native static String lookupDev(StringBuilder errbuf);

	/**
	 * Lookup net.
	 * 
	 * @param device
	 *          the device
	 * @param netp
	 *          the netp
	 * @param maskp
	 *          the maskp
	 * @param errbuf
	 *          the errbuf
	 * @return the int
	 */
	public native static int lookupNet(
	    String device,
	    JNumber netp,
	    JNumber maskp,
	    StringBuilder errbuf);

	/**
	 * Lookup net.
	 * 
	 * @param device
	 *          the device
	 * @param netp
	 *          the netp
	 * @param maskp
	 *          the maskp
	 * @param errbuf
	 *          the errbuf
	 * @return the int
	 */
	public native static int lookupNet(
	    String device,
	    PcapInteger netp,
	    PcapInteger maskp,
	    StringBuilder errbuf);

	/**
	 * Open dead.
	 * 
	 * @param linktype
	 *          the linktype
	 * @param snaplen
	 *          the snaplen
	 * @return the pcap
	 */
	public native static Pcap openDead(int linktype, int snaplen);

	/**
	 * Open live.
	 * 
	 * @param device
	 *          the device
	 * @param snaplen
	 *          the snaplen
	 * @param promisc
	 *          the promisc
	 * @param timeout
	 *          the timeout
	 * @param errbuf
	 *          the errbuf
	 * @return the pcap
	 */
	public native static Pcap openLive(
	    String device,
	    int snaplen,
	    int promisc,
	    int timeout,
	    StringBuilder errbuf);

	/**
	 * Open offline.
	 * 
	 * @param fname
	 *          the fname
	 * @param errbuf
	 *          the errbuf
	 * @return the pcap
	 */
	public native static Pcap openOffline(String fname, StringBuilder errbuf);

	/** The physical. */
	private volatile long physical;

	/**
	 * Instantiates a new pcap.
	 */
	public Pcap() {
		// Empty on purpose, the private field 'physical' is initialized
		// from JNI call. That is the only way it can be initialized.
	}

	/**
	 * Breakloop.
	 */
	public native void breakloop();

	/**
	 * Check is active.
	 * 
	 * @throws PcapClosedException
	 *           the pcap closed exception
	 */
	protected native void checkIsActive() throws PcapClosedException;

	/**
	 * Close.
	 */
	public native void close();

	/**
	 * Compile.
	 * 
	 * @param program
	 *          the program
	 * @param str
	 *          the str
	 * @param optimize
	 *          the optimize
	 * @param netmask
	 *          the netmask
	 * @return the int
	 */
	public native int compile(
	    PcapBpfProgram program,
	    String str,
	    int optimize,
	    int netmask);

	/**
	 * Datalink.
	 * 
	 * @return the int
	 */
	public native int datalink();

	/**
	 * Datalink to id.
	 * 
	 * @return the int
	 */
	private int datalinkToId() {
		int id = JRegistry.mapDLTToId(datalink());

		return (id == JRegistry.NO_DLT_MAPPING) ? JProtocol.ETHERNET_ID : id;

	}

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int dispatch(int cnt, ByteBufferHandler<T> handler, T user) {
		return dispatch(cnt, handler, user, new PcapHeader(Type.POINTER));
	}

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param header
	 *          the header
	 * @return the int
	 */
	private native <T> int dispatch(
	    int cnt,
	    ByteBufferHandler<T> handler,
	    T user,
	    PcapHeader header);

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param id
	 *          the id
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int dispatch(int cnt, int id, JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, id, handler, user, packet, packet.getState(), packet
		    .getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param id
	 *          the id
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param packet
	 *          the packet
	 * @param state
	 *          the state
	 * @param header
	 *          the header
	 * @param scanner
	 *          the scanner
	 * @return the int
	 */
	private native <T> int dispatch(
	    int cnt,
	    int id,
	    JPacketHandler<T> handler,
	    T user,
	    JPacket packet,
	    JPacket.State state,
	    PcapHeader header,
	    JScanner scanner);

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param id
	 *          the id
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int dispatch(int cnt, int id, PcapPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, id, handler, user, packet, packet.getState(), packet
		    .getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param id
	 *          the id
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param packet
	 *          the packet
	 * @param state
	 *          the state
	 * @param header
	 *          the header
	 * @param scanner
	 *          the scanner
	 * @return the int
	 */
	private native <T> int dispatch(
	    int cnt,
	    int id,
	    PcapPacketHandler<T> handler,
	    T user,
	    JPacket packet,
	    JPacket.State state,
	    PcapHeader header,
	    JScanner scanner);

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int dispatch(int cnt, JBufferHandler<T> handler, T user) {
		return dispatch(cnt, handler, user, new PcapHeader(Type.POINTER),
		    new JBuffer(Type.POINTER));
	}

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	private native <T> int dispatch(
	    int cnt,
	    JBufferHandler<T> handler,
	    T user,
	    PcapHeader header,
	    JBuffer buffer);

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int dispatch(int cnt, JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, datalinkToId(), handler, user, packet, packet
		    .getState(), packet.getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param scanner
	 *          the scanner
	 * @return the int
	 */
	public <T> int dispatch(
	    int cnt,
	    JPacketHandler<T> handler,
	    T user,
	    JScanner scanner) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, datalinkToId(), handler, user, packet, packet
		    .getState(), packet.getCaptureHeader(), scanner);
	}

	/**
	 * Dispatch.
	 * 
	 * @param cnt
	 *          the cnt
	 * @param dumper
	 *          the dumper
	 * @return the int
	 */
	public native int dispatch(int cnt, PcapDumper dumper);

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public native <T> int dispatch(int cnt, PcapHandler<T> handler, T user);

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int dispatch(int cnt, PcapPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, datalinkToId(), handler, user, packet, packet
		    .getState(), packet.getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Dispatch.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param scanner
	 *          the scanner
	 * @return the int
	 */
	public <T> int dispatch(
	    int cnt,
	    PcapPacketHandler<T> handler,
	    T user,
	    JScanner scanner) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return dispatch(cnt, datalinkToId(), handler, user, packet, packet
		    .getState(), packet.getCaptureHeader(), scanner);
	}

	/**
	 * Dump open.
	 * 
	 * @param fname
	 *          the fname
	 * @return the pcap dumper
	 */
	public native PcapDumper dumpOpen(String fname);

	/* (non-Javadoc)
	 * @see java.lang.Object#finalize()
	 */
	@Override
	protected void finalize() {
		if (physical != 0) {
			close();
		}
	}

	/**
	 * Gets the err.
	 * 
	 * @return the err
	 */
	public native String getErr();

	/**
	 * Gets the non block.
	 * 
	 * @param errbuf
	 *          the errbuf
	 * @return the non block
	 */
	public native int getNonBlock(StringBuilder errbuf);

	/**
	 * Inject.
	 * 
	 * @param buf
	 *          the buf
	 * @return the int
	 */
	public int inject(final byte[] buf) {
		checkIsActive(); // Check if Pcap.close wasn't called

		final int length = buf.length;
		final ByteBuffer direct = ByteBuffer.allocateDirect(length);
		direct.put(buf);

		return injectPrivate(direct, 0, length);
	}

	/**
	 * Inject.
	 * 
	 * @param buf
	 *          the buf
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the int
	 */
	public int inject(final byte[] buf, int offset, int length) {
		checkIsActive(); // Check if Pcap.close wasn't called

		final ByteBuffer direct = ByteBuffer.allocateDirect(length);
		direct.put(buf, offset, length);

		return injectPrivate(direct, 0, length);
	}

	/**
	 * Inject.
	 * 
	 * @param buf
	 *          the buf
	 * @return the int
	 */
	public int inject(final ByteBuffer buf) {
		checkIsActive(); // Check if Pcap.close wasn't called

		if (buf.isDirect() == false) {
			final int length = buf.limit() - buf.position();
			final ByteBuffer direct = ByteBuffer.allocateDirect(length);
			direct.put(buf);

			return injectPrivate(direct, 0, length);
		} else {
			return injectPrivate(buf, buf.position(), buf.limit() - buf.position());
		}
	}

	/**
	 * Inject.
	 * 
	 * @param buf
	 *          the buf
	 * @param start
	 *          the start
	 * @param len
	 *          the len
	 * @return the int
	 */
	public native int inject(JBuffer buf, int start, int len);

	/**
	 * Inject private.
	 * 
	 * @param buf
	 *          the buf
	 * @param start
	 *          the start
	 * @param len
	 *          the len
	 * @return the int
	 */
	private native int injectPrivate(ByteBuffer buf, int start, int len);

	/**
	 * Checks if is swapped.
	 * 
	 * @return the int
	 */
	public native int isSwapped();

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int loop(int cnt, ByteBufferHandler<T> handler, T user) {
		return loop(cnt, handler, user, new PcapHeader(Type.POINTER));
	}

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param header
	 *          the header
	 * @return the int
	 */
	private native <T> int loop(
	    int cnt,
	    ByteBufferHandler<T> handler,
	    T user,
	    PcapHeader header);

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param id
	 *          the id
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int loop(int cnt, int id, JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(cnt, id, handler, user, packet, packet.getState(), packet
		    .getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param id
	 *          the id
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param packet
	 *          the packet
	 * @param state
	 *          the state
	 * @param header
	 *          the header
	 * @param scanner
	 *          the scanner
	 * @return the int
	 */
	private native <T> int loop(
	    int cnt,
	    int id,
	    JPacketHandler<T> handler,
	    T user,
	    JPacket packet,
	    JPacket.State state,
	    PcapHeader header,
	    JScanner scanner);

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param id
	 *          the id
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int loop(int cnt, int id, PcapPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(cnt, id, handler, user, packet, packet.getState(), packet
		    .getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param id
	 *          the id
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param packet
	 *          the packet
	 * @param state
	 *          the state
	 * @param header
	 *          the header
	 * @param scanner
	 *          the scanner
	 * @return the int
	 */
	private native <T> int loop(
	    int cnt,
	    int id,
	    PcapPacketHandler<T> handler,
	    T user,
	    JPacket packet,
	    JPacket.State state,
	    PcapHeader header,
	    JScanner scanner);

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int loop(int cnt, JBufferHandler<T> handler, T user) {
		return loop(cnt, handler, user, new PcapHeader(Type.POINTER), new JBuffer(
		    Type.POINTER));
	}

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	private native <T> int loop(
	    int cnt,
	    JBufferHandler<T> handler,
	    T user,
	    PcapHeader header,
	    JBuffer buffer);

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int loop(int cnt, JPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(cnt, datalinkToId(), handler, user, packet, packet.getState(),
		    packet.getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param scanner
	 *          the scanner
	 * @return the int
	 */
	public <T> int loop(
	    int cnt,
	    JPacketHandler<T> handler,
	    T user,
	    JScanner scanner) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(cnt, datalinkToId(), handler, user, packet, packet.getState(),
		    packet.getCaptureHeader(), scanner);
	}

	/**
	 * Loop.
	 * 
	 * @param cnt
	 *          the cnt
	 * @param dumper
	 *          the dumper
	 * @return the int
	 */
	public native int loop(int cnt, PcapDumper dumper);

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public native <T> int loop(int cnt, PcapHandler<T> handler, T user);

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @return the int
	 */
	public <T> int loop(int cnt, PcapPacketHandler<T> handler, T user) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(cnt, datalinkToId(), handler, user, packet, packet.getState(),
		    packet.getCaptureHeader(), JScanner.getThreadLocal());
	}

	/**
	 * Loop.
	 * 
	 * @param <T>
	 *          the generic type
	 * @param cnt
	 *          the cnt
	 * @param handler
	 *          the handler
	 * @param user
	 *          the user
	 * @param scanner
	 *          the scanner
	 * @return the int
	 */
	public <T> int loop(
	    int cnt,
	    PcapPacketHandler<T> handler,
	    T user,
	    JScanner scanner) {
		final PcapPacket packet = new PcapPacket(Type.POINTER);
		return loop(cnt, datalinkToId(), handler, user, packet, packet.getState(),
		    packet.getCaptureHeader(), scanner);
	}

	/**
	 * Major version.
	 * 
	 * @return the int
	 */
	public native int majorVersion();

	/**
	 * Minor version.
	 * 
	 * @return the int
	 */
	public native int minorVersion();

	/**
	 * Next.
	 * 
	 * @param pkt_header
	 *          the pkt_header
	 * @param buffer
	 *          the buffer
	 * @return the j buffer
	 */
	public native JBuffer next(PcapHeader pkt_header, JBuffer buffer);

	/**
	 * Next.
	 * 
	 * @param pkt_header
	 *          the pkt_header
	 * @return the byte buffer
	 */
	public native ByteBuffer next(PcapPktHdr pkt_header);

	/**
	 * Next ex.
	 * 
	 * @param pkt_header
	 *          the pkt_header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public native int nextEx(PcapHeader pkt_header, JBuffer buffer);

	/**
	 * Next ex.
	 * 
	 * @param packet
	 *          the packet
	 * @return the int
	 */
	public int nextEx(PcapPacket packet) {
		int r = nextEx(packet.getCaptureHeader(), packet);

		packet.scan(JRegistry.mapDLTToId(datalink()));

		return r;
	}

	/**
	 * Next ex.
	 * 
	 * @param pkt_header
	 *          the pkt_header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public native int nextEx(PcapPktHdr pkt_header, PcapPktBuffer buffer);

	/**
	 * Send packet.
	 * 
	 * @param buf
	 *          the buf
	 * @return the int
	 */
	public int sendPacket(final byte[] buf) {
		checkIsActive(); // Check if Pcap.close wasn't called

		final int length = buf.length;
		final ByteBuffer direct = ByteBuffer.allocateDirect(length);
		direct.put(buf);

		return sendPacketPrivate(direct, 0, length);
	}

	/**
	 * Send packet.
	 * 
	 * @param buf
	 *          the buf
	 * @param offset
	 *          the offset
	 * @param length
	 *          the length
	 * @return the int
	 */
	public int sendPacket(final byte[] buf, int offset, int length) {
		checkIsActive(); // Check if Pcap.close wasn't called

		final ByteBuffer direct = ByteBuffer.allocateDirect(length);
		direct.put(buf, offset, length);

		return sendPacketPrivate(direct, 0, length);
	}

	/**
	 * Send packet.
	 * 
	 * @param buf
	 *          the buf
	 * @return the int
	 */
	public int sendPacket(final ByteBuffer buf) {
		checkIsActive(); // Check if Pcap.close wasn't called

		if (buf.isDirect() == false) {
			final int length = buf.limit() - buf.position();
			final ByteBuffer direct = ByteBuffer.allocateDirect(length);
			direct.put(buf);

			return sendPacketPrivate(direct, 0, length);
		} else {
			return sendPacketPrivate(buf, buf.position(), buf.limit()
			    - buf.position());
		}
	}

	/**
	 * Send packet.
	 * 
	 * @param buf
	 *          the buf
	 * @return the int
	 */
	public native int sendPacket(final JBuffer buf);

	/**
	 * Send packet private.
	 * 
	 * @param buf
	 *          the buf
	 * @param start
	 *          the start
	 * @param len
	 *          the len
	 * @return the int
	 */
	private native int sendPacketPrivate(ByteBuffer buf, int start, int len);

	/**
	 * Sets the datalink.
	 * 
	 * @param dlt
	 *          the dlt
	 * @return the int
	 */
	public native int setDatalink(int dlt);

	/**
	 * Sets the filter.
	 * 
	 * @param program
	 *          the program
	 * @return the int
	 */
	public native int setFilter(PcapBpfProgram program);

	/**
	 * Sets the non block.
	 * 
	 * @param nonBlock
	 *          the non block
	 * @param errbuf
	 *          the errbuf
	 * @return the int
	 */
	public native int setNonBlock(int nonBlock, StringBuilder errbuf);

	/**
	 * Snapshot.
	 * 
	 * @return the int
	 */
	public native int snapshot();

	/**
	 * Stats.
	 * 
	 * @param stats
	 *          the stats
	 * @return the int
	 */
	public native int stats(PcapStat stats);

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
  public String toString() {
		checkIsActive(); // Check if Pcap.close wasn't called

		return libVersion();
	}

}
