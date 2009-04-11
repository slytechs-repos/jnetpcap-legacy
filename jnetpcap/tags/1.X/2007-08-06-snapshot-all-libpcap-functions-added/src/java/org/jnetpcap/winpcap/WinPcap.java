/**
 * Copyright (C) 2007 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.winpcap;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHandler;

/**
 * WinPcap specific extensions to libpcap library. To access WinPcap extensions,
 * you must use WinPcap class and its methods. <code>WinPcap</code> class
 * extends Pcap class so you have all of the typeical <code>Pcap</code> class
 * functionality. WinPcap provides many additional methods which are only
 * available on platforms what support WinPcap. First you must use static
 * <code>WinPcap.isSupported()</code> method call which will return a boolean
 * that will indicate if WinPcap extensions are supported on this particular
 * platform. If you try and use any method in this class when WinPcap extensions
 * are not supported, another words <code>WinPcap.isSupport()</code> returned
 * false, every method in this calls will throw
 * <code>UnsupportOperationException</code>.
 * 
 * @see Pcap
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class WinPcap
    extends Pcap {

	/**
	 * Initialize JNI method, field and class IDs.
	 */
	private static native void initIDs();

	static {
		initIDs();
	}

	/**
	 * Checks if WinPcap extensions are available on this platform.
	 * 
	 * @return true means WinPcap extensions are available and loaded, otherwise
	 *         false
	 */
	public static native boolean isSupported();

	/**
	 * Create a pcap_t structure without starting a capture. pcap_open_dead() is
	 * used for creating a pcap_t structure to use when calling the other
	 * functions in libpcap. It is typically used when just using libpcap for
	 * compiling BPF code.
	 * 
	 * @see Pcap#openDead(int, int)
	 * @param linktype
	 *          pcap DLT link type integer value
	 * @param snaplen
	 *          filters generated using the pcap structure will truncate captured
	 *          packets to this length
	 * @return WinPcap structure that can only be used to generate filter code and
	 *         none of its other capture methods should be called or null if error
	 *         occured
	 */
	public native static WinPcap openDead(int linktype, int snaplen);

	/**
	 * <p>
	 * This method, overrides the generic libpcap based <code>openLive</code>
	 * method, and allocates a peer pcap object that allows WinPcap extensions.
	 * </p>
	 * <p>
	 * Open a live capture associated with the specified network interface device.
	 * pcap_open_live() is used to obtain a packet capture descriptor to look at
	 * packets on the network. device is a string that specifies the network
	 * device to open; on Linux systems with 2.2 or later kernels, a device
	 * argument of "any" or NULL can be used to capture packets from all
	 * interfaces. snaplen specifies the maximum number of bytes to capture. If
	 * this value is less than the size of a packet that is captured, only the
	 * first snaplen bytes of that packet will be captured and provided as packet
	 * data. A value of 65535 should be sufficient, on most if not all networks,
	 * to capture all the data available from the packet. promisc specifies if the
	 * interface is to be put into promiscuous mode. (Note that even if this
	 * parameter is false, the interface could well be in promiscuous mode for
	 * some other reason.)
	 * </p>
	 * <p>
	 * For now, this doesn't work on the "any" device; if an argument of "any" or
	 * NULL is supplied, the promisc flag is ignored. to_ms specifies the read
	 * timeout in milliseconds. The read timeout is used to arrange that the read
	 * not necessarily return immediately when a packet is seen, but that it wait
	 * for some amount of time to allow more packets to arrive and to read
	 * multiple packets from the OS kernel in one operation. Not all platforms
	 * support a read timeout; on platforms that don't, the read timeout is
	 * ignored. A zero value for to_ms, on platforms that support a read timeout,
	 * will cause a read to wait forever to allow enough packets to arrive, with
	 * no timeout. errbuf is used to return error or warning text. It will be set
	 * to error text when pcap_open_live() fails and returns NULL. errbuf may also
	 * be set to warning text when pcap_open_live() succeds; to detect this case
	 * the caller should store a zero-length string in errbuf before calling
	 * pcap_open_live() and display the warning to the user if errbuf is no longer
	 * a zero-length string.
	 * </p>
	 * <p>
	 * <b>Special note about <code>snaplen</code> argument.</b> The behaviour
	 * of this argument may be suprizing to some. The <code>argument</code> is
	 * only applied when there is a filter set using <code>setFilter</code>
	 * method after the <code>openLive</code> call. Otherwise snaplen, even non
	 * zero is ignored. This is the behavior of all BSD systems utilizing BPF and
	 * WinPcap. This may change in the future, but that is the current behavior.
	 * (For more detailed explanation and discussion please see jNetPcap website
	 * and its FAQs.)
	 * </p>
	 * 
	 * @see Pcap#openLive(String, int, int, int, StringBuilder)
	 * @param device
	 *          buffer containing a C, '\0' terminated string with the the name of
	 *          the device
	 * @param snaplen
	 *          amount of data to capture per packet; (see special note in doc
	 *          comments about when this argument is ignored even when non-zero)
	 * @param promisc
	 *          1 means open in promiscious mode, a 0 means non-propmiscous
	 * @param timeout
	 *          timeout in ms
	 * @param errbuf
	 *          a buffer that will contain any error messages if the call to open
	 *          failed
	 * @return a raw structure the data of <code>pcap_t</code> C structure as
	 *         returned by native libpcap call to open
	 */
	public native static WinPcap openLive(String device, int snaplen,
	    int promisc, int timeout, StringBuilder errbuf);

	/**
	 * Open a savefile in the tcpdump/libpcap format to read packets.
	 * pcap_open_offline() is called to open a "savefile" for reading. fname
	 * specifies the name of the file to open. The file has the same format as
	 * those used by tcpdump(1) and tcpslice(1). The name "-" in a synonym for
	 * stdin. Alternatively, you may call pcap_fopen_offline() to read dumped data
	 * from an existing open stream fp. Note that on Windows, that stream should
	 * be opened in binary mode. errbuf is used to return error text and is only
	 * set when pcap_open_offline() or pcap_fopen_offline() fails and returns
	 * NULL.
	 * 
	 * @see Pcap#openOffline(String, StringBuilder)
	 * @param fname
	 *          filename of the pcap file
	 * @param errbuf
	 *          any error messages in UTC8 encoding
	 * @return WinPcap structure or null if error occured
	 */
	public native static WinPcap openOffline(String fname, StringBuilder errbuf);

	/**
	 * WinPcap objects make no sense unless they have been allocated from JNI
	 * space and the physical address field has been set in super.physical.
	 */
	private WinPcap() {
		super();
	}

	/**
	 * Set the size of the kernel buffer associated with an adapter. If an old
	 * buffer was already created with a previous call to pcap_setbuff(), it is
	 * deleted and its content is discarded. pcap_open_live() creates a 1 MByte
	 * buffer by default.
	 * 
	 * @see #openLive(String, int, int, int, StringBuilder)
	 * @see #loop(int, PcapHandler, Object)
	 * @see #dispatch(int, PcapHandler, Object)
	 * @param dim
	 *          specifies the size of the buffer in bytes
	 * @return the return value is 0 when the call succeeds, -1 otherwise
	 */
	public native int setBuff(int dim);

	/**
	 * Set the working mode of the interface p to mode. Valid values for mode are
	 * MODE_CAPT (default capture mode) and MODE_STAT (statistical mode).
	 * 
	 * @param mode
	 *          pcap capture mode
	 * @return the return value is 0 when the call succeeds, -1 otherwise
	 */
	public native int setMode(int mode);

	/**
	 * Set the minumum amount of data received by the kernel in a single call.
	 * pcap_setmintocopy() changes the minimum amount of data in the kernel buffer
	 * that causes a read from the application to return (unless the timeout
	 * expires). If the value of size is large, the kernel is forced to wait the
	 * arrival of several packets before copying the data to the user. This
	 * guarantees a low number of system calls, i.e. low processor usage, and is a
	 * good setting for applications like packet-sniffers and protocol analyzers.
	 * Vice versa, in presence of a small value for this variable, the kernel will
	 * copy the packets as soon as the application is ready to receive them. This
	 * is useful for real time applications that need the best responsiveness from
	 * the kernel.
	 * 
	 * @see #openLive(String, int, int, int, StringBuilder)
	 * @see #loop(int, PcapHandler, Object)
	 * @see #dispatch(int, PcapHandler, Object)
	 * @param size
	 *          minimum size
	 * @return the return value is 0 when the call succeeds, -1 otherwise
	 */
	@SuppressWarnings("unused")
	private int setMinToCopy(int size) {
		throw new UnsatisfiedLinkError("Not supported in this version of Libpcap");
	}

}
