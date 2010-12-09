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
package org.jnetpcap.winpcap;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapExtensionNotAvailableException;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapPktHdr;
import org.jnetpcap.nio.JBuffer;

// TODO: Auto-generated Javadoc
/**
 * The Class WinPcap.
 */
@SuppressWarnings("deprecation")
public class WinPcap
    extends Pcap {

	/** The Constant buf. */
	private final static ThreadLocal<StringBuffer> buf =
	    new ThreadLocal<StringBuffer>() {

		    @Override
		    protected StringBuffer initialValue() {
			    return new StringBuffer();
		    }

	    };

	/** The Constant MODE_CAPT. */
	public static final int MODE_CAPT = 0;

	/** The Constant MODE_MONITOR. */
	public static final int MODE_MONITOR = 2;

	/** The Constant MODE_STAT. */
	public static final int MODE_STAT = 1;

	/** The Constant OPENFLAG_DATATX_UDP. */
	public final static int OPENFLAG_DATATX_UDP = 2;

	/** The Constant OPENFLAG_MAX_RESPONSIVENESS. */
	public final static int OPENFLAG_MAX_RESPONSIVENESS = 16;

	/** The Constant OPENFLAG_NOCAPTURE_LOCAL. */
	public final static int OPENFLAG_NOCAPTURE_LOCAL = 8;

	/** The Constant OPENFLAG_NOCAPTURE_RPCAP. */
	public final static int OPENFLAG_NOCAPTURE_RPCAP = 4;

	/** The Constant SRC_FILE. */
	public final static int SRC_FILE = 2;

	/** The Constant SRC_IFLOCAL. */
	public final static int SRC_IFLOCAL = 3;

	/** The Constant SRC_IFREMOTE. */
	public final static int SRC_IFREMOTE = 4;

	/** The Constant TRANSMIT_SYNCH_ASAP. */
	public static final int TRANSMIT_SYNCH_ASAP = 0;

	/** The Constant TRANSMIT_SYNCH_USE_TIMESTAMP. */
	public static final int TRANSMIT_SYNCH_USE_TIMESTAMP = 1;

	static {
		initIDs();

		// Make sure some dependency classes get loaded
		try {
			Class.forName("org.jnetpcap.winpcap.WinPcapStat");
			Class.forName("org.jnetpcap.winpcap.WinPcapSamp");
		} catch (final ClassNotFoundException e) {
			throw new IllegalStateException("Unable to find class: ", e);
		}
	}

	/**
	 * As string.
	 * 
	 * @param bs
	 *          the bs
	 * @return the string
	 */
	private static String asString(byte[] bs) {
		StringBuilder buf = new StringBuilder();
		for (byte b : bs) {
			if (buf.length() != 0) {
				buf.append(':');
			}
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		}

		return buf.toString();
	}

	/**
	 * Creates the src str.
	 * 
	 * @param source
	 *          the source
	 * @param type
	 *          the type
	 * @param host
	 *          the host
	 * @param port
	 *          the port
	 * @param name
	 *          the name
	 * @param errbuf
	 *          the errbuf
	 * @return the int
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static int createSrcStr(Appendable source, int type, String host,
	    String port, String name, Appendable errbuf) throws IOException {

		final StringBuffer buf2 = new StringBuffer();

		final int r = createSrcStr(buf2, type, host, port, name, getBuf());

		toAppendable(getBuf(), errbuf);
		toAppendable(buf2, source);

		return r;
	}

	/**
	 * Creates the src str.
	 * 
	 * @param source
	 *          the source
	 * @param type
	 *          the type
	 * @param host
	 *          the host
	 * @param port
	 *          the port
	 * @param name
	 *          the name
	 * @param errbuf
	 *          the errbuf
	 * @return the int
	 */
	public native static int createSrcStr(StringBuffer source, int type,
	    String host, String port, String name, StringBuffer errbuf);

	/**
	 * Creates the src str.
	 * 
	 * @param source
	 *          the source
	 * @param type
	 *          the type
	 * @param host
	 *          the host
	 * @param port
	 *          the port
	 * @param name
	 *          the name
	 * @param errbuf
	 *          the errbuf
	 * @return the int
	 */
	public static int createSrcStr(StringBuilder source, int type, String host,
	    String port, String name, StringBuilder errbuf) {

		final StringBuffer buf2 = new StringBuffer();

		final int r = createSrcStr(buf2, type, host, port, name, getBuf());

		toStringBuilder(getBuf(), errbuf);
		toStringBuilder(buf2, source);

		return r;
	}

	/**
	 * Find all devs ex.
	 * 
	 * @param source
	 *          the source
	 * @param auth
	 *          the auth
	 * @param alldevs
	 *          the alldevs
	 * @param errbuf
	 *          the errbuf
	 * @return the int
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static int findAllDevsEx(String source, WinPcapRmtAuth auth,
	    List<PcapIf> alldevs, Appendable errbuf) throws IOException {
		final int r = findAllDevsEx(source, auth, alldevs, getBuf());

		toAppendable(getBuf(), errbuf);

		return r;
	}

	/**
	 * Find all devs ex.
	 * 
	 * @param source
	 *          the source
	 * @param auth
	 *          the auth
	 * @param alldevs
	 *          the alldevs
	 * @param errbuf
	 *          the errbuf
	 * @return the int
	 */
	public native static int findAllDevsEx(String source, WinPcapRmtAuth auth,
	    List<PcapIf> alldevs, StringBuffer errbuf);

	/**
	 * Find all devs ex.
	 * 
	 * @param source
	 *          the source
	 * @param auth
	 *          the auth
	 * @param alldevs
	 *          the alldevs
	 * @param errbuf
	 *          the errbuf
	 * @return the int
	 */
	public static int findAllDevsEx(String source, WinPcapRmtAuth auth,
	    List<PcapIf> alldevs, StringBuilder errbuf) {
		final int r = findAllDevsEx(source, auth, alldevs, getBuf());

		toStringBuilder(getBuf(), errbuf);

		return r;
	}

	/**
	 * Gets the make sure that we are thread safe and don't clober each others
	 * messages.
	 * 
	 * @return the make sure that we are thread safe and don't clober each others
	 *         messages
	 */
	private static StringBuffer getBuf() {
		return buf.get();
	}

	/**
	 * Inits the i ds.
	 */
	private static native void initIDs();

	/**
	 * Checks if is supported.
	 * 
	 * @return true, if is supported
	 */
	public static native boolean isSupported();

	/**
	 * Offline filter.
	 * 
	 * @param program
	 *          the program
	 * @param caplen
	 *          the caplen
	 * @param len
	 *          the len
	 * @param buf
	 *          the buf
	 * @return the int
	 */
	public static native int offlineFilter(PcapBpfProgram program, int caplen,
	    int len, ByteBuffer buf);

	/**
	 * Offline filter.
	 * 
	 * @param program
	 *          the program
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public static native int offlineFilter(PcapBpfProgram program,
	    PcapHeader header, ByteBuffer buffer);

	/**
	 * Offline filter.
	 * 
	 * @param program
	 *          the program
	 * @param header
	 *          the header
	 * @param buffer
	 *          the buffer
	 * @return the int
	 */
	public static native int offlineFilter(PcapBpfProgram program,
	    PcapHeader header, JBuffer buffer);

	/**
	 * Offline filter.
	 * 
	 * @param program
	 *          the program
	 * @param header
	 *          the header
	 * @param buf
	 *          the buf
	 * @return the int
	 */
	public static native int offlineFilter(PcapBpfProgram program,
	    PcapPktHdr header, ByteBuffer buf);

	/**
	 * Open.
	 * 
	 * @param source
	 *          the source
	 * @param snaplen
	 *          the snaplen
	 * @param flags
	 *          the flags
	 * @param timeout
	 *          the timeout
	 * @param auth
	 *          the auth
	 * @param errbuf
	 *          the errbuf
	 * @return the win pcap
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static WinPcap open(String source, int snaplen, int flags,
	    int timeout, WinPcapRmtAuth auth, Appendable errbuf) throws IOException {
		final WinPcap r = open(source, snaplen, flags, timeout, auth, getBuf());

		toAppendable(getBuf(), errbuf);

		return r;
	}

	/**
	 * Open.
	 * 
	 * @param source
	 *          the source
	 * @param snaplen
	 *          the snaplen
	 * @param flags
	 *          the flags
	 * @param timeout
	 *          the timeout
	 * @param auth
	 *          the auth
	 * @param errbuf
	 *          the errbuf
	 * @return the win pcap
	 */
	public native static WinPcap open(String source, int snaplen, int flags,
	    int timeout, WinPcapRmtAuth auth, StringBuffer errbuf);

	/**
	 * Open.
	 * 
	 * @param source
	 *          the source
	 * @param snaplen
	 *          the snaplen
	 * @param flags
	 *          the flags
	 * @param timeout
	 *          the timeout
	 * @param auth
	 *          the auth
	 * @param errbuf
	 *          the errbuf
	 * @return the win pcap
	 */
	public static WinPcap open(String source, int snaplen, int flags,
	    int timeout, WinPcapRmtAuth auth, StringBuilder errbuf) {
		final WinPcap r = open(source, snaplen, flags, timeout, auth, getBuf());

		toStringBuilder(getBuf(), errbuf);

		return r;
	}

	/**
	 * Open dead.
	 * 
	 * @param linktype
	 *          the linktype
	 * @param snaplen
	 *          the snaplen
	 * @return the win pcap
	 */
	public native static WinPcap openDead(int linktype, int snaplen);

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
	 * @return the win pcap
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static WinPcap openLive(String device, int snaplen, int promisc,
	    int timeout, Appendable errbuf) throws IOException {
		final WinPcap r = openLive(device, snaplen, promisc, timeout, getBuf());

		toAppendable(getBuf(), errbuf);

		return r;
	}

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
	 * @return the win pcap
	 */
	public native static WinPcap openLive(String device, int snaplen,
	    int promisc, int timeout, StringBuffer errbuf);

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
	 * @return the win pcap
	 */
	public static WinPcap openLive(String device, int snaplen, int promisc,
	    int timeout, StringBuilder errbuf) {
		final WinPcap r = openLive(device, snaplen, promisc, timeout, getBuf());

		toStringBuilder(getBuf(), errbuf);

		return r;
	}

	/**
	 * Open offline.
	 * 
	 * @param fname
	 *          the fname
	 * @param errbuf
	 *          the errbuf
	 * @return the win pcap
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	public static WinPcap openOffline(String fname, Appendable errbuf)
	    throws IOException {
		final WinPcap r = openOffline(fname, getBuf());

		toAppendable(getBuf(), errbuf);

		return r;
	}

	/**
	 * Open offline.
	 * 
	 * @param fname
	 *          the fname
	 * @param errbuf
	 *          the errbuf
	 * @return the win pcap
	 */
	public native static WinPcap openOffline(String fname, StringBuffer errbuf);

	/**
	 * Open offline.
	 * 
	 * @param fname
	 *          the fname
	 * @param errbuf
	 *          the errbuf
	 * @return the win pcap
	 */
	public static WinPcap openOffline(String fname, StringBuilder errbuf) {
		final WinPcap r = openOffline(fname, getBuf());

		toStringBuilder(getBuf(), errbuf);

		return r;
	}

	/**
	 * Send queue alloc.
	 * 
	 * @param size
	 *          the size
	 * @return the win pcap send queue
	 */
	public static WinPcapSendQueue sendQueueAlloc(final int size) {

		if (isSupported() == false) {
			throw new PcapExtensionNotAvailableException();
		}

		return new WinPcapSendQueue(size);
	}

	/**
	 * Send queue destroy.
	 * 
	 * @param queue
	 *          the queue
	 */
	public static void sendQueueDestroy(final WinPcapSendQueue queue) {

		if (isSupported() == false) {
			throw new PcapExtensionNotAvailableException();
		}

		// Memory is recaptured during GC
	}

	/**
	 * To appendable.
	 * 
	 * @param buf
	 *          the buf
	 * @param appendable
	 *          the appendable
	 * @throws IOException
	 *           Signals that an I/O exception has occurred.
	 */
	private static void toAppendable(StringBuffer buf, Appendable appendable)
	    throws IOException {

		if (buf.length() != 0) {
			appendable.append(buf);
		}
	}

	/**
	 * To string builder.
	 * 
	 * @param buf
	 *          the buf
	 * @param builder
	 *          the builder
	 */
	private static void toStringBuilder(StringBuffer buf, StringBuilder builder) {
		builder.setLength(0);

		if (buf.length() != 0) {
			builder.append(buf);
		}
	}

	/**
	 * Instantiates a new win pcap.
	 */
	private WinPcap() {
		super();
	}

	/**
	 * Live dump.
	 * 
	 * @param fname
	 *          the fname
	 * @param maxsize
	 *          the maxsize
	 * @param maxpackets
	 *          the maxpackets
	 * @return the int
	 */
	public native int liveDump(String fname, int maxsize, int maxpackets);

	/**
	 * Live dump ended.
	 * 
	 * @param sync
	 *          the sync
	 * @return the int
	 */
	public native int liveDumpEnded(int sync);

	/**
	 * Send queue transmit.
	 * 
	 * @param queue
	 *          the queue
	 * @param synch
	 *          the synch
	 * @return the int
	 */
	public native int sendQueueTransmit(final WinPcapSendQueue queue,
	    final int synch);

	/**
	 * Sets the buff.
	 * 
	 * @param dim
	 *          the dim
	 * @return the int
	 */
	public native int setBuff(int dim);

	/**
	 * Sets the min to copy.
	 * 
	 * @param size
	 *          the size
	 * @return the int
	 */
	public native int setMinToCopy(int size);

	/**
	 * Sets the mode.
	 * 
	 * @param mode
	 *          the mode
	 * @return the int
	 */
	public native int setMode(int mode);

	/**
	 * Sets the sampling.
	 * 
	 * @return the win pcap samp
	 */
	public native WinPcapSamp setSampling();

	/**
	 * Stats ex.
	 * 
	 * @return the win pcap stat
	 */
	public native WinPcapStat statsEx();
}
