/**
 * $Id$ Copyright (C) 2006 Sly Technologies, Inc. This library is free software;
 * you can redistribute it and/or modify it under the terms of the GNU Lesser
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

import java.nio.ByteBuffer;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * <P>
 * This class is the main wrapper around libpcap and winpcap library
 * impelementations. It provides a direct mapping of various library methods
 * from Java.
 * </P>
 * <h2>Getting started</h2>
 * <p>
 * <code>Pcap</code> class provides several static methods which allow
 * discovery of networking interfaces and then subsequently open up either
 * <code>openLive</code>, <code>openDead</code> or <code>openOffline</code>
 * pcap capture sessions. In all 3 cases a <code>Pcap</code> object is
 * returned. The object is backed by a C <code>pcap_t</code> structure outside
 * of java VM address space. Any non-static operations on the <code>Pcap</code>
 * object, are translated using java JNI API into corresponding Libpcap C calls
 * and the appropriate <code>pcap_t</code> C structure is supplied to complete
 * the call.
 * </p>
 * <p>
 * After aquiring a <code>Pcap</code> object from above mentioned static
 * methods, you must call on {@link #close} call to release any Libpcap
 * resources and the backing C structure. The <code>Pcap</code> object does
 * implicitly call the {@link #close} method from its {@link #finalize} method,
 * but that will only happen when the <code>Pcap</code> is garabage collected.
 * Its best practice to remember to always call on {@link #close} when
 * <code>Pcap</code> object and capture session is no longer needed.
 * </p>
 * <p>
 * If <code>Pcap</code> object is closed and any of its non-static methods are
 * called on, after the close, {@link IllegalStateException} will be thrown.
 * </p>
 * <h3>Getting a list of network interfaces from Pcap</h3>
 * Lets get started with little example on how to inquire about available
 * interfaces, ask the user to pick one of those interfaces for us, open it for
 * capture, compile and install a capture filter and then start processing some
 * packets captured as a result. This is all loosely based on examples you will
 * find on tcpdump.org website but updated for jNetPCAP. As with libpcap, we
 * first want to find out and get network interface names so we can tell
 * jNetPCAP to open one or more for reading. So first we inquire about the list
 * of interfaces on the system:
 * 
 * <pre>
 * StringBuilder errbuf = new StringBuilder();
 * List&lt;PcapIf&gt; ifs = new ArrayList&lt;PcapIf&gt;(); // Will hold list of devices
 * int statusCode = Pcap.findAllDevs(ifs, errbuf);
 * if (statusCode != Pcap.OK) {
 * 	System.out.println(&quot;Error occured: &quot; + errbuf.toString());
 * 	return;
 * }
 * // We have a list of PcapIf devices to work with now.
 * 
 * </pre>
 * 
 * <p>
 * <b>Note:</b> the return value from {@link #findAllDevs} is an integer result
 * code, just like in the C counter part. The <code>ifs</code> list is filled
 * in with all the network devices as found from the corresponding C structure
 * <code>pcap_if</code> linked list returned from the C function call
 * findAllDevs.
 * </p>
 * <p>
 * Now that we have a list of devices, we we print out the list of them and ask
 * the user to pick one to open for capture:
 * 
 * <pre>
 * for (int i = 0; i &lt; ifs.size(); i++) {
 * 	System.out.println(&quot;#&quot; + i + &quot;: &quot; + ifs.get(i).getName());
 * }
 * 
 * String l = System.in.readline().trim();
 * Integer i = Integer.valueOf(l);
 * 
 * PcapIf netInterface = ifs.get(i);
 * </pre>
 * 
 * <h3>Opening a network interface for live capture</h3>
 * Next we open up a live capture from the network interface using
 * {@link #openLive(String, int, int, int, StringBuilder)}:
 * 
 * <pre>
 * int snalen = 2048; // Truncate packet at this size
 * 
 * int promiscous = Pcap.MODE_PROMISCUOUS;
 * 
 * int timeout = 60 * 1000; // In milliseconds
 * 
 * Pcap pcap = Pcap.openLive(netInterface.getName(), snaplen, promiscous, timeout,
 *     errbuf);
 * </pre>
 * 
 * Last argument is a buffer that will hold an error string, if error occures.
 * On error <code>openLive</code> will return null.
 * <h3>Compiling and applying a filter to network interface</h3>
 * Once we have an open interface for capture we can apply a filter to reduce
 * amount of packets captured to something that is interesting to us:
 * 
 * <pre>
 * PcapBpfProgram filter = new PcapBpfProgram();
 * String expression = &quot;port 23&quot;
 * int optimize = 0; // 1 means true, 0 means false
 * int netmask = 0;
 * 
 * int r = pcap.compile(filter, expression, optimize, netmask);
 * if (r != Pcap.OK) {
 *   System.out.println(&quot;Filter error: &quot; + pcap.getErr());
 * }
 * pcap.setFilter(filter);
 * </pre>
 * 
 * <p>
 * If filter expression contained a syntax error, the return code will be -1 and
 * exact error message can be retrieved using {@link #getErr} method.
 * </p>
 * <p>
 * <b>Note of caution:</b> the <code>PcapBpfProgram</code> at the top of the
 * previous code section, can not be accessed until successfully filled in with
 * values in the <code>pcap.compile</code> code. If you try and access any of
 * its methods an <code>IllegalStateException</code> will be thrown. Only
 * after a successful call to <code>compile</code> does the object become
 * usable. The object is peered with C structure and until properly intialized,
 * can not be accessed from java.
 * </p>
 * <h3> Dispatcher to receive packets as they arrive</h3>
 * And lastly lets do something with the data.
 * 
 * <pre>
 * 
 * PcapHandler handler = new PcapHandler() {
 * 
 * 	public void newPacket(Object userData, int caplen, int len, int seconds,
 * 	    int usecs, ByteBuffer buffer) {
 * 
 * 		PrintStream out = (PrintStream) userData;
 * 		out.println(&quot;Packet captured on: &quot; + new Date(seconds * 1000).toString());
 * 	}
 * };
 * 
 * int cnt = 10; // Capture packet count
 * PrintStream out = System.out; // Our custom object to send into the handler
 * 
 * pcap.loop(cnt, handler, out); // Each packet will be dispatched to the handler
 * 
 * pcap.close();
 * </pre>
 * 
 * <p>
 * This sets up PCAP to capture 10 packets and notify our handler of each packet
 * as each one is captured. Then after 10 packets the loop exits and we call
 * pcap.close() to free up all the resources and we can safely throw away our
 * pcap object. Also you may be curious why we pass System.out as userData to
 * the loop handler. This is simply to demonstrate the typical usage for this
 * kind of parameter. In our case we could easily pass a different PrintStream
 * bound to lets say a network socket and our handler would produce output to
 * it.
 * </p>
 * <p>
 * Alternative way of capturing packets from any of the open pcap sessions is to
 * use {@link #dispatch(int, PcapHandler, Object)} method, which works very
 * similarly to {@link #loop(int, PcapHandler, Object)}. You can also use
 * {@link #next(PcapPkthdr)} and {@link #nextEx(PcapPkthdr, PcapPktbuffer)}
 * methods which will deliver 1 packet at a time.
 * </p>
 * <h3>No packet data copies!</h3>
 * <p>
 * The packet data is delivered in a <code>java.nio.ByteBuffer</code>. The
 * data is not copied into the buffer, but a direct byte buffer is allocated and
 * wrapped around the packet data as returned from libpcap. No in memory copies
 * are performed, so if the native operating system supports no-copy packet
 * captures, the packet are delived to Java without copies. Only a single
 * ByteBuffer object allocation is incured.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Pcap {

	/**
	 * Holds the exception thrown from the static initializer only. After its been
	 * reset by the init() function, this field is never set again.
	 */
	private static Exception initError;

	/**
	 * Name of the dynamically loaded shared library (a .dll on windows and .so on
	 * unix machines.) OS dependent library extension or prefixes are not and
	 * should not be part of this name field.
	 */
	private static final String JNI_SHARED_LIBRARY_NAME = "jnetpcap";

	/**
	 * Boolean flag to tell if JNI shared library initialized itself properly
	 * after it was loaded. Init uses it to try and re-initialize the JNI library
	 * by calling its jniInitialize() method and it failed the last time.
	 */
	private static boolean jniInitStatus = false;

	/**
	 * Boolean flag to tell if the library loaded succesfully. Init uses it to try
	 * and reload the library if it failed and init was called again by the user.
	 */
	private static boolean libraryLoadStatus = false;

	private static final Log logger = LogFactory.getLog(Pcap.class);

	/**
	 * Value of packet count argument for <code>loop</code> method call which
	 * indicates that the loop should never exit, unless an error occured or
	 * <code>breakloop</code> call was used to interrupt the dispatcher. Note,
	 * that this constant is not appropriate value for <code>dispatch</code>
	 * method call, which has a different meaning.
	 */
	public static final int LOOP_INFINATE = -1;

	/**
	 * Value of packet count argument for <code>dispatch</code> method call
	 * which indicates that only as many packets should be returned as will fit in
	 * a single buffer , unless an error occured or <code>breakloop</code> call
	 * was used to interrupt the dispatcher. Note, that this constant is only
	 * appropriate value for <code>dispatch</code> method call. Loop method uses
	 * LOOP_INFINATE for something similar, but definately not identical to this
	 * option.
	 */
	public static final int DISPATCH_BUFFER_FULL = -1;

	/**
	 * Pcap status return code for <code>loop</code> and <code>dispatch</code>
	 * methods. This status code indicates that the the dispatcher was interrupted
	 * by a call to <code>breakloop</code> call.
	 */
	public static final int LOOP_INTERRUPTED = -2;

	/**
	 * Flag which can be used with <code>setNonBlock</code> method to set the
	 * previously opened pcap descriptor into 'blocking' mode. The flag can also
	 * be the return code from <code>getNonBlock</code>. The flag has no affect
	 * on 'savefiles'.
	 */
	public static final int MODE_BLOCKING = 0;

	/**
	 * Flag which can be used with <code>setNonBlock</code> method to set the
	 * previously opened pcap descriptor into 'non-blocking' mode. The flag can
	 * also be the return code from <code>getNonBlock</code>. The flag has no
	 * affect on 'savefiles'.
	 */
	public static final int MODE_NON_BLOCKING = 1;

	/**
	 * Flag used with <code>openLive</code> to specify that the interface should
	 * not be put into promisuous mode, but only if poassible. Note, the even
	 * though the flag is specified, the interface could still be opened in
	 * promiscous mode for other reasons, such as a different process had already
	 * put the interface into promiscuous mode.
	 */
	public static final int MODE_NON_PROMISCUOUS = 0;

	/**
	 * Flag used with <code>openLive</code> to specify that the interface should
	 * be put into promisuous mode.
	 */
	public static final int MODE_PROMISCUOUS = 1;

	/**
	 * Pcap status return code for most of the methods defined here. All methods
	 * that return an intenger as a status code, use this constants as meaning the
	 * call failed.
	 */
	public static final int NOT_OK = -1;

	/**
	 * Pcap status return code for most of the methods defined here. All methods
	 * that return an intenger as a status code, use this constants as meaning the
	 * call succeeded.
	 */
	public static final int OK = 0;

	/**
	 * Exit code for <code>nextEx</code> method which indicates success.
	 */
	public static final int NEXT_EX_OK = 1;

	/**
	 * Exit code for <code>nextEx</code> method which indicates timeout has
	 * expired before a packet was captured. The packet header and packet buffer
	 * do no point to any valid data.
	 */
	public static final int NEXT_EX_TIMEDOUT = 0;

	/**
	 * Exit code for <code>nextEx</code> method which indicates failure of some
	 * kind. Use {@link #getErr()} to retrieve the error message.
	 */
	public static final int NEXT_EX_NOT_OK = -1;

	/**
	 * Exit code for <code>nextEx</code> method which indicates that pcap
	 * reached end of file while reading a 'savefile'.
	 */
	public static final int NEXT_EX_EOF = -2;

	/**
	 * Static initializer
	 */
	static {
		try {
			init();
		} catch (Exception e) {
			initError = e;
			logger.error("Unable to initialize JNI from static initializer: "
			    + e.toString(), e);
		}
	}

	/**
	 * This method checks the status of the initialization squence started in
	 * static initializer right when the class was first loaded.
	 * 
	 * @return null is returned on success otherwise the exception that caused the
	 *         failure
	 */
	public static Exception checkStaticInitializerError() {
		return initError;
	}

	/**
	 * <p>
	 * Compile a packet filter without the need of opening an adapter. This
	 * function converts an high level filtering expression (see Filtering
	 * expression syntax) in a program that can be interpreted by the kernel-level
	 * filtering engine.
	 * </p>
	 * <p>
	 * pcap_compile_nopcap() is similar to pcap_compile() except that instead of
	 * passing a pcap structure, one passes the snaplen and linktype explicitly.
	 * It is intended to be used for compiling filters for direct BPF usage,
	 * without necessarily having called pcap_open(). (pcap_compile_nopcap() is a
	 * wrapper around pcap_open_dead(), pcap_compile(), and pcap_close(); the
	 * latter three routines can be used directly in order to get the error text
	 * for a compilation error.)
	 * </p>
	 * <p>
	 * Look at the Filtering expression syntax section for details on the str
	 * parameter.
	 * </p>
	 * 
	 * @param snaplen
	 *          generate code to truncate packets to this length upon a match
	 * @param dlt
	 *          the first header type within the packet, or data link type of the
	 *          interface
	 * @param program
	 *          initially empty, but after the method call will contain the
	 *          compiled BPF program
	 * @param str
	 *          a string containing the textual expression to be compiled
	 * @param optimize
	 *          1 means to do optimizations, any other value means no
	 * @param netmask
	 *          netmask needed to determine the broadcast address
	 * @return a return of -1 indicates an error; the error text is unavailable
	 */
	public native static int compileNoPcap(int snaplen, int dlt,
	    PcapBpfProgram program, String str, int optimize, int netmask);

	/**
	 * Translates a data link type name, which is a DLT_ name with the DLT_
	 * removed, to the corresponding data link type value. The translation is
	 * case-insensitive. -1 is returned on failure.
	 * 
	 * @param name
	 *          data link type name
	 * @return data link type value or -1 on failure
	 */
	public native static int datalinkNameToVal(String name);

	/**
	 * Translates a data link type value to a short description of that data link
	 * type. NULL is returned on failure.
	 * 
	 * @param dlt
	 *          data link type value
	 * @return short description of that data link type, NULL is returned on
	 *         failure
	 */
	public native static String datalinkValToDescription(int dlt);

	/**
	 * Translates a data link type value to the corresponding data link type name.
	 * NULL is returned on failure.
	 * 
	 * @param dlt
	 *          data link type value
	 * @return data link type value to the corresponding data link type name, NULL
	 *         is returned on failure
	 */
	public native static String datalinkValToName(int dlt);

	/**
	 * pcap_findalldevs() constructs a list of network devices that can be opened
	 * with pcap_open_live(). (Note that there may be network devices that cannot
	 * be opened with pcap_open_live() by the process calling pcap_findalldevs(),
	 * because, for example, that process might not have sufficient privileges to
	 * open them for capturing; if so, those devices will not appear on the list.)
	 * alldevs is set to point to the first element of the list; each element of
	 * the list is of type pcap_if_t, and has the following members:
	 * <ul>
	 * <li>next if not NULL, a pointer to the next element in the list; NULL for
	 * the last element of the list
	 * <li>name a pointer to a string giving a name for the device to pass to
	 * pcap_open_live()
	 * <li>description if not NULL, a pointer to a string giving a human-readable
	 * description of the device
	 * <li>addresses a pointer to the first element of a list of addresses for
	 * the interface
	 * <li>flags interface flags: PCAP_IF_LOOPBACK set if the interface is a
	 * loopback interface
	 * </ul>
	 * Each element of the list of addresses is of type pcap_addr_t, and has the
	 * following members:
	 * <ul>
	 * <li>next if not NULL, a pointer to the next element in the list; NULL for
	 * the last element of the list
	 * <li>addr a pointer to a struct sockaddr containing an address
	 * <li>netmask if not NULL, a pointer to a struct sockaddr that contains the
	 * netmask corresponding to the address pointed to by addr
	 * <li>broadaddr if not NULL, a pointer to a struct sockaddr that contains
	 * the broadcast address corresponding to the address pointed to by addr; may
	 * be null if the interface doesn't support broadcasts
	 * <li>dstaddr if not NULL, a pointer to a struct sockaddr that contains the
	 * destination address corresponding to the address pointed to by addr; may be
	 * null if the interface isn't a point-to-point interface
	 * </ul>
	 * 
	 * @param alldevs
	 *          the list is filled in with <code>PcapIf</code> interface
	 *          objects; the list must not be immutable
	 * @param errbuf
	 *          error buffer containing error message as a string on failure
	 * @return -1 is returned on failure, in which case errbuf is filled in with
	 *         an appropriate error message; 0 is returned on success
	 */
	public native static int findAllDevs(List<PcapIf> alldevs,
	    StringBuilder errbuf);

	/**
	 * This method does nothing. jNetPcap implementation frees up the device list
	 * immediately after its copied into Java objects in java space. The source
	 * structures are immediately released. pcap_freealldevs() is used to free a
	 * list allocated by pcap_findalldevs().
	 * 
	 * @param alldevs
	 *          is set to point to the first element of the list; each element of
	 *          the list is of type PcapIf
	 * @param errbuf
	 *          error buffer containing error message as a string on failure
	 */
	public static void freeAllDevs(List<PcapIf> alldevs, byte[] errbuf) {
		// Empty do nothing method, java PcapIf objects currently have no link
		// to C structures and do not need to be freed up. All the C structures
		// used to building PcapIf chains are already free.
		if (alldevs == null || errbuf == null) {
			throw new NullPointerException();
		}
	}

	/**
	 * This method forces deallocation of backend resources. After this call, any
	 * access to the BPF program through any of its accessor methods, will result
	 * in IllegalStateException raised. The user should release any references to
	 * the java object after this call.
	 * 
	 * @param program
	 *          program to free up the backend resources for
	 */
	public native static void freecode(PcapBpfProgram program);

	/**
	 * Initializes the jNetPcap library JNI component. This method is called
	 * automatically by this class's static initializer and usually does not need
	 * to be called again. Before calling on init, you should first check with
	 * {@link #checkStaticInitializerError} method to see if the static
	 * initializer generated any error. If there was an error, then you can try
	 * and recover, after which init may be called again. Init does not catch any
	 * exceptions that might be thrown from native initializer or library load
	 * function. The method clears the error status as returned by
	 * {@link #checkStaticInitializerError} and this error is never set again. All
	 * error are thrown immediately from this time forward by this method.
	 * 
	 * @throws UnsatisfiedLinkError
	 *           if native JNI shared library can not be found
	 * @throws SecurityException
	 *           if you don't have permission to load the JNI shared library
	 * @throws IllegalStateException
	 *           something terribly wrong during JNI initialization sequence
	 * @throws ClassNotFoundException
	 *           JNI unable to locate required class and aquire its handle
	 * @throws NoSuchMethodException
	 *           the class was found, but did not contain the required method and
	 *           JNI was unable to aquire its handle
	 * @throws NoSuchFieldException
	 *           the class was found, but did not contain the required field and
	 *           JNI was unable to aquire its handle
	 */
	public static void init() throws UnsatisfiedLinkError, SecurityException,
	    IllegalStateException, ClassNotFoundException, NoSuchMethodException,
	    NoSuchFieldException {

		initError = null; // Clear previous error if any

		if (libraryLoadStatus == false) {
			System.loadLibrary(JNI_SHARED_LIBRARY_NAME);
			libraryLoadStatus = true; // Library loaded OK
		}

		if (jniInitStatus == false) {
			initIDs();
			jniInitStatus = true;
		}

	}

	// public native int loop(int cnt, PcapHandler heandler, Object user);

	/**
	 * Initializes JNI. Mainly prefetches all the JNI class, method and field IDs
	 * for everything that jnetpcap shared library needs inorder to interact with
	 * Java VM. This is done once and never has to be redone again. Once both the
	 * library are loaded and then JNI properly initializes itself, this method
	 * will have no effect.
	 * 
	 * @throws IllegalStateException
	 *           something terribly wrong during JNI initialization sequence
	 * @throws ClassNotFoundException
	 *           JNI unable to locate required class and aquire its handle
	 * @throws NoSuchMethodException
	 *           the class was found, but did not contain the required method and
	 *           JNI was unable to aquire its handle
	 * @throws NoSuchFieldException
	 *           the class was found, but did not contain the required field and
	 *           JNI was unable to aquire its handle
	 */
	private native static void initIDs() throws IllegalStateException,
	    ClassNotFoundException, NoSuchMethodException, NoSuchFieldException;

	/**
	 * Returns a pointer to a string giving information about the version of the
	 * libpcap library being used; note that it contains more information than
	 * just a version number
	 * 
	 * @return version of the libpcap library being used
	 */
	public native static String libVersion();

	/**
	 * Create a pcap_t structure without starting a capture. pcap_open_dead() is
	 * used for creating a pcap_t structure to use when calling the other
	 * functions in libpcap. It is typically used when just using libpcap for
	 * compiling BPF code.
	 * 
	 * @param linktype
	 *          pcap DLT link type integer value
	 * @param snaplen
	 *          filters generated using the pcap structure will truncate captured
	 *          packets to this length
	 * @return Pcap structure that can only be used to generate filter code and
	 *         none of its other capture methods should be called or null if error
	 *         occured
	 */
	public native static Pcap openDead(int linktype, int snaplen);

	/**
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
	 * 
	 * @param device
	 *          buffer containing a C, '\0' terminated string with the the name of
	 *          the device
	 * @param snaplen
	 *          amount of data to capture per packet
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
	public native static Pcap openLive(String device, int snaplen, int promisc,
	    int timeout, StringBuilder errbuf);

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
	 * @param fname
	 *          filename of the pcap file
	 * @param errbuf
	 *          any error messages in UTC8 encoding
	 * @return Pcap structure or null if error occured
	 */
	public native static Pcap openOffline(String fname, StringBuilder errbuf);

	/**
	 * Physical address of the corresponding <code>pcap_t</code> C structure on
	 * native machine. <i>Libpcap</i> allocated this structure and deallocates it
	 * when {@link #close} is called. This is the reason that in
	 * {@link #finalize()} we call {@link #close} explicitely to let <i>Libpcap</i>
	 * free up the structure.
	 */
	private final long physical;

	/**
	 * Pcap object can only be created by calling one of the static
	 * {@link #openLive} methods.
	 */
	private Pcap(long physical) {
		this.physical = physical;
	}

	/**
	 * <p>
	 * set a flag that will force pcap_dispatch() or pcap_loop() to return rather
	 * than looping. They will return the number of packets that have been
	 * processed so far, or -2 if no packets have been processed so far. This
	 * routine is safe to use inside a signal handler on UNIX or a console control
	 * handler on Windows, as it merely sets a flag that is checked within the
	 * loop. The flag is checked in loops reading packets from the OS - a signal
	 * by itself will not necessarily terminate those loops - as well as in loops
	 * processing a set of packets returned by the OS. Note that if you are
	 * catching signals on UNIX systems that support restarting system calls after
	 * a signal, and calling pcap_breakloop() in the signal handler, you must
	 * specify, when catching those signals, that system calls should NOT be
	 * restarted by that signal. Otherwise, if the signal interrupted a call
	 * reading packets in a live capture, when your signal handler returns after
	 * calling pcap_breakloop(), the call will be restarted, and the loop will not
	 * terminate until more packets arrive and the call completes.
	 * </p>
	 * <p>
	 * Note: pcap_next() will, on some platforms, loop reading packets from the
	 * OS; that loop will not necessarily be terminated by a signal, so
	 * pcap_breakloop() should be used to terminate packet processing even if
	 * pcap_next() is being used. pcap_breakloop() does not guarantee that no
	 * further packets will be processed by pcap_dispatch() or pcap_loop() after
	 * it is called; at most one more packet might be processed. If -2 is returned
	 * from pcap_dispatch() or pcap_loop(), the flag is cleared, so a subsequent
	 * call will resume reading packets. If a positive number is returned, the
	 * flag is not cleared, so a subsequent call will return -2 and clear the
	 * flag.
	 * </p>
	 */
	public native void breakloop();

	/**
	 * pcap_close() closes the files associated with p and deallocates resources.
	 */
	public native void close();

	/**
	 * @param program
	 *          initially empty, but after the method call will contain the
	 *          compiled BPF program
	 * @param str
	 *          a string containing the textual expression to be compiled
	 * @param optimize
	 *          1 means to do optimizations, any other value means no
	 * @param netmask
	 *          netmask needed to determine the broadcast address
	 * @return A return of -1 indicates an error in which case {@link #getErr()}
	 *         may be used to display the error text.
	 */
	public native int compile(PcapBpfProgram program, String str, int optimize,
	    int netmask);

	/**
	 * Returns the link layer of an adapter.
	 * 
	 * @return PCAP link layer number
	 */
	public native int datalink();

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
	 * 
	 * @param cnt
	 *          number of packets to read
	 * @param handler
	 *          called when packet arrives for each packet
	 * @param user
	 *          opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 */
	public native int dispatch(int cnt, PcapHandler handler, Object user);

	/**
	 * Cleanup before we're GCed. Will close connection to any open interface.
	 * Does nothing if connection already closed.
	 */
	protected void finalize() {
		if (physical != 0) {
			close();
		}
	}

	/**
	 * return the error text pertaining to the last pcap library error.
	 * <p>
	 * Note: the pointer Return will no longer point to a valid error message
	 * string after the pcap_t passed to it is closed; you must use or copy the
	 * string before closing the pcap_t.
	 * </p>
	 * 
	 * @return the error text pertaining to the last pcap library error
	 */
	public native String getErr();

	/**
	 * pcap_getnonblock() returns the current ``non-blocking'' state of the
	 * capture descriptor; it always returns 0 on ``savefiles''. If there is an
	 * error, -1 is returned and errbuf is filled in with an appropriate error
	 * message.
	 * 
	 * @see #setNonBlock(int, StringBuilder)
	 * @return if there is an error, -1 is returned and errbuf is filled in with
	 *         an appropriate error message
	 */
	public native int getNonBlock(StringBuilder errbuf);

	/**
	 * returns true if the current savefile uses a different byte order than the
	 * current system
	 * 
	 * @return 0 is false, non-zero is true
	 */
	public native int isSwapped();

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
	 * 
	 * @param cnt
	 *          number of packets to read
	 * @param handler
	 *          called when packet arrives for each packet
	 * @param user
	 *          opaque user object
	 * @return 0 on success, -1 on error and -2 if breakloop was used interrupt
	 *         the captue
	 */
	public native int loop(int cnt, PcapHandler handler, Object user);

	/**
	 * Return the major version number of the pcap library used to write the
	 * savefile.
	 * 
	 * @return return the major version number of the pcap library used to write
	 *         the savefile
	 */
	public native int majorVersion();

	/**
	 * Return the minor version number of the pcap library used to write the
	 * savefile.
	 * 
	 * @return return the minor version number of the pcap library used to write
	 *         the savefile
	 */
	public native int minorVersion();

	/**
	 * Return the next available packet. pcap_next() reads the next packet (by
	 * calling pcap_dispatch() with a cnt of 1) and returns a u_char pointer to
	 * the data in that packet. (The pcap_pkthdr struct for that packet is not
	 * supplied.) NULL is returned if an error occured, or if no packets were read
	 * from a live capture (if, for example, they were discarded because they
	 * didn't pass the packet filter, or if, on platforms that support a read
	 * timeout that starts before any packets arrive, the timeout expires before
	 * any packets arrive, or if the file descriptor for the capture device is in
	 * non-blocking mode and no packets were available to be read), or if no more
	 * packets are available in a ``savefile.'' Unfortunately, there is no way to
	 * determine whether an error occured or not.
	 * 
	 * @param pkt_header
	 *          a packet header that will be initialized to corresponding C
	 *          structure captured values
	 * @return buffer containing packet data or null if error occured
	 */
	public native ByteBuffer next(PcapPkthdr pkt_header);

	/**
	 * Read a packet from an interface or from an offline capture. This function
	 * is used to retrieve the next available packet, bypassing the callback
	 * method traditionally provided by libpcap. pcap_next_ex fills the pkt_header
	 * and pkt_data parameters (see pcap_handler()) with the pointers to the
	 * header and to the data of the next captured packet.
	 * </p>
	 * 
	 * @param pkt_header
	 *          a packet header that will be initialized to corresponding C
	 *          structure captured values
	 * @param buffer
	 *          buffer containing packet data or null if error occured
	 * @return the status code
	 *         <ul>
	 *         <li>1 if the packet has been read without problems
	 *         <li>0 if the timeout set with pcap_open_live() has elapsed. In
	 *         this case pkt_header and pkt_data don't point to a valid packet
	 *         <li>-1 if an error occurred
	 *         <li>-2 if EOF was reached reading from an offline capture
	 *         </ul>
	 */
	public native int nextEx(PcapPkthdr pkt_header, PcapPktbuffer buffer);

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
	 * Set the current data link type of the pcap descriptor to the type specified
	 * by dlt.
	 * 
	 * @param dlt
	 *          new dlt
	 * @return -1 is returned on failure
	 */
	public native int setDatalink(int dlt);

	/**
	 * Associate a filter to a capture. pcap_setfilter() is used to specify a
	 * filter program. fp is a pointer to a bpf_program struct, usually the result
	 * of a call to pcap_compile(). -1 is returned on failure, in which case
	 * pcap_geterr() may be used to display the error text; 0 is returned on
	 * success.
	 * 
	 * @param program
	 * @return -1 is returned on failure, in which case pcap_geterr() may be used
	 *         to display the error text; 0 is returned on success
	 */
	public native int setFilter(PcapBpfProgram program);

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
	 * pcap_setnonblock() puts a capture descriptor, opened with pcap_open_live(),
	 * into ``non-blocking'' mode, or takes it out of ``non-blocking'' mode,
	 * depending on whether the nonblock argument is non-zero or zero. It has no
	 * effect on ``savefiles''. If there is an error, -1 is returned and errbuf is
	 * filled in with an appropriate error message; otherwise, 0 is returned. In
	 * ``non-blocking'' mode, an attempt to read from the capture descriptor with
	 * pcap_dispatch() will, if no packets are currently available to be read,
	 * return 0 immediately rather than blocking waiting for packets to arrive.
	 * pcap_loop() and pcap_next() will not work in ``non-blocking'' mode.
	 * 
	 * @see #getNonBlock(StringBuilder)
	 * @param nonBlock
	 *          a non negative value means to set in non blocking mode
	 * @return if there is an error, -1 is returned and errbuf is filled in with
	 *         an appropriate error message
	 */
	public native int setNonBlock(int nonBlock, StringBuilder errbuf);

	/**
	 * Return the dimension of the packet portion (in bytes) that is delivered to
	 * the application. pcap_snapshot() returns the snapshot length specified when
	 * pcap_open_live was called.
	 * 
	 * @see #openLive(String, int, int, int, StringBuilder)
	 * @return the snapshot length specified when pcap_open_live was called
	 */
	public native int snapshot();

	public String toString() {
		return "jNetPcap based on " + libVersion();
	}
}
