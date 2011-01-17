/**
 * Copyright (C) 2010 Sly Technologies, Inc. This library is free software; you
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
package org.jnetpcap.compatibility;

import org.jnetpcap.Pcap;
import org.jnetsoft.library.APIDescriptor;
import org.jnetsoft.library.Library;

/**
 * Libpcap 1.0.0 feature set definition. This class provides an extension
 * mechanism to load libpcap 1.0.0 features on top of various actual libpcap
 * implementations installed on the system. This feature set, explicitly is
 * limited to new function calls that were made available with libpcap 1.0.0
 * API. All other libpcap calls that were available before libpcap 1.0.0 was
 * released, are not part of this API definition. This API is also refered to as
 * Funct which stands for libpcap version 1.0.0 in compressed form.
 * <p>
 * If the currently installed libpcap library implementation supports libpcap
 * 1.0.0 calls, or another words, libpcap 1.0.0 or greater is installed,
 * jnetpcap's Funct extensions (also in native library) will be loaded by JVM if
 * found. Otherwise if new libpcap calls do not exist, native runtime linker
 * will not be able to resolve all the references made from Funct library to
 * currently installed libpcap library and fail to load this API extension.
 * </p>
 * <p>
 * This class reports the results of the attempt to load Funct native library in
 * constants {@link #IS_LOADED} and errors in {@link #LOAD_EXCEPTION}.
 * </p>
 * <p>
 * The user can check at runtime if Pcap100 API is available, if everything was
 * loaded properly and the calls are actually implemented, by checking the
 * {@link #IS_IMPLEMENTED} boolean constant.
 * 
 * <pre>
 * if (Funct.IS_IMPLEMENTED) {
 * 	// We can safely use Funct API calls and constructs
 * } else {
 * 	// Revert to non Funct calls
 * }
 * </pre>
 * 
 * Alternatively, a library can be loaded, but not neccessarily implemented. API
 * calls that are not implemented always return UnsupportedOperationException.
 * 
 * <pre>
 * if (Funct.IS_LOADED) {
 * 	if (Funct.IS_IMPLEMENTED) {
 * 		// We can safely use Funct API calls and constructs
 * 	} else {
 * 		// Revert to non Funct calls
 * 	}
 * }
 * </pre>
 * 
 * But since if IS_IMPLEMENTED is true, then the library must have been loaded
 * in the first place. Thus a single Funct.IS_IMPLEMENTED check is sufficient to
 * make a decision about API usage.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Pcap100
    extends
    Pcap {

	/**
	 * A table for libpcap 1.0.0 (Pcap100) calls that makeup this API.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	private enum Call {
		/**
		 * pcap_activate
		 */
		PCAP_ACTIVATE(0),

		/**
		 * pcap_can_set_rfmon
		 */
		PCAP_CAN_SET_RFMON(1),

		/**
		 * pcap_create
		 */
		PCAP_CREATE(8),

		/**
		 * pcap_set_buffer_size
		 */
		PCAP_SET_BUFFER_SIZE(3),

		/**
		 * pcap_set_direction
		 */
		PCAP_SET_DIRECTION(4),

		/**
		 * pcap_set_promisc
		 */
		PCAP_SET_PROMISC(5),

		/**
		 * pcap_set_rfmon
		 */
		PCAP_SET_RFMON(2),

		/**
		 * pcap_set_snaplen
		 */
		PCAP_SET_SNAPLEN(6),

		/**
		 * pcap_set_timeout
		 */
		PCAP_SET_TIMEOUT(7), ;

		/**
		 * Index into the native vtable to dispatch calls
		 */
		private final int index;

		private Call(int index) {
			this.index = index;
		}
	};

	/**
	 * Allows us to manipulate JNI native method registries. This API class has to
	 * natively implement a api_vtable and provide a method that will create and
	 * peer a APIDescriptor object to that table. This table is used to proviate
	 * JNI registry services.
	 */
	private final static APIDescriptor API;

	/**
	 * Direction constant for use with {@link #setDirection(int) setDirection}
	 * which indicates the inbound direction
	 */
	public static final int IN = 1;

	/**
	 * Direction constant for use with {@link #setDirection(int) setDirection}
	 * which indicates both in and out directions
	 */
	public static final int INOUT = 0;

	/**
	 * Flag which indicates if the API implementation is actually implemented or
	 * are all function calls just stubs that throw UnsupportedOperationException
	 * even though appropriate libpcap may be installed on the system.
	 * <p>
	 * A library that is implemented is also loaded. So in order to actually rely
	 * on this API calls doing actual work, the user must use IS_IMPLEMENTED as a
	 * check in their code.
	 * </p>
	 * <p>
	 * Unimplemented API calls are actually stub native functions that throw an
	 * exception immediately. This condition can happen on platforms where
	 * jNetPcap was compiled against libpcap version that did not support the
	 * required API calls. In that particular scenario, the build scripts compile
	 * a stub to throw a more user frielndly UnsupportOperationException instead
	 * of a lower level UnsatisfiedLinkError exception due to JVM failure to bind
	 * a native function to java native method.
	 * </p>
	 * 
	 * @see #IS_LOADED
	 */
	public final static boolean IS_IMPLEMENTED;

	/**
	 * Flag which indicates if the native library, implementing Funct API (API
	 * defined as of libpcap 1.0.0), loaded successfully
	 * 
	 * @see #IS_IMPLEMENTED
	 */
	public final static boolean IS_LOADED;

	/**
	 * Name of the native library. The name is without library postfix which is
	 * not portable between different operating systems (i.e. dll for windows and
	 * so for *NIX.)
	 */
	public final static String LIBRARY_NAME = "jnetpcap-pcap100";

	/**
	 * Error exception if the library failed to load successfully
	 */
	public final static UnsatisfiedLinkError LOAD_EXCEPTION;

	/**
	 * Message constants that is never null, even when there was not error on
	 * library load. This constant is suitable to be used with jUnit assert
	 * functions since its never null and can be used as the message part of the
	 * assert function.
	 */
	public final static String LOAD_EXCEPTION_MESSAGE;

	/*
	 * A word about @SupporWarning("all"). The javac/IDEs generate warnings about
	 * @Override missing because he inherit from Pcap and we should override these
	 * functions. That is true when these native API calls are implemented in the
	 * base version of Pcap, but because this API class is portable and be used
	 * with older jnetcap versions where these are not implemented, ther @Override
	 * is unwanted. Therefore we explicitely disable that particular warning.
	 */

	/**
	 * Direction constant for use with {@link #setDirection(int) setDirection}
	 * which indicates the outbound direction
	 */
	public static final int OUT = 2;

	static {

		UnsatisfiedLinkError error = null;
		
		if (!Pcap080.IS_LOADED) {
			/*
			 * We need Pcap080 in order to function. If we don't load the main library
			 * we have to abort
			 */
			throw Pcap080.LOAD_EXCEPTION;
		}

		/*
		 * We try and load the libpcap 1.0.0 API compatibility library.
		 */
		try {
			Library.loadLibrary(LIBRARY_NAME, "jnetpcap", "libpcap");

		} catch (UnsatisfiedLinkError e) {
			error = e;
		}

		if (error == null) {
			IS_LOADED = true;
			IS_IMPLEMENTED = isImplemented();
			LOAD_EXCEPTION = null;
			LOAD_EXCEPTION_MESSAGE = "";
		} else {
			IS_LOADED = false;
			IS_IMPLEMENTED = false;
			LOAD_EXCEPTION = error;
			LOAD_EXCEPTION_MESSAGE = error.getMessage();
		}

		/**
		 * Force native call bindings to this class
		 */
		if (IS_LOADED) {
			API = createAPIDescriptor();
			/*
			 * Override the default binding. Instead of to "create" method which we
			 * made in Pcap100 public (to match Pcap.create signature, JNI doesn't
			 * allow us to up typecast to Pcap100), we bind to "createPrivate" which
			 * is a private method. This allows us to typecast to Pcap100 class, since
			 * we can not change the signature of the "create" method to return
			 * anything except a Pcap class type object (a JNI restriction, not java).
			 */
			API.register(Pcap100.class, Call.PCAP_CREATE.index, "createPrivate");

			if (API.registerAllExcept(Pcap100.class, Call.PCAP_CREATE.index) != 0) {
				System.err.printf("Failed to register Pcap100 API Natives%n");
			}
		} else {
			API = null;
		}
	}

	/**
	 * pcap_create() is used to create a packet capture handle to look at packets
	 * on the network. source is a string that specifies the network device to
	 * open; on Linux systems with 2.2 or later kernels, a source argument of
	 * "any" or NULL can be used to capture packets from all interfaces. The
	 * returned handle must be activated with pcap_activate() before pack' ets can
	 * be captured with it; options for the capture, such as promiscu' ous mode,
	 * can be set on the handle before activating it.
	 * 
	 * @param device
	 *          a string that specifies the network device to open; on Linux
	 *          systems with 2.2 or later kernels, a source argument of "any" or
	 *          NULL can be used to capture packets from all interfaces.
	 * @param errbuf
	 *          If NULL is returned, errbuf is filled in with an appropriate error
	 *          mes' sage
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 * @since 1.4
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static Pcap100 create(String device, StringBuilder errbuf) {
		return (Pcap100) createPrivate(device, errbuf);
	}

	/**
	 * Creates an API descriptor. The descriptor holds reference to dispatch table
	 * for API functions.
	 * 
	 * @return A API descriptor for this API
	 */
	private native static APIDescriptor createAPIDescriptor();

	/**
	 * Private version of pcap_create that is compatible with main Pcap.create's
	 * signature. A private version is used, so that we can typecast the return
	 * value to Pcap100 safely, from plain Pcap, in the public method
	 * {@link #create(String, StringBuilder)}.
	 * 
	 * @param device
	 *          a string that specifies the network device to open; on Linux
	 *          systems with 2.2 or later kernels, a source argument of "any" or
	 *          NULL can be used to capture packets from all interfaces.
	 * @param errbuf
	 *          If NULL is returned, errbuf is filled in with an appropriate error
	 *          mes' sage
	 * @return a new pcap object that needs to be activated using
	 *         {@link #activate()} call
	 */
	private native static Pcap createPrivate(String device, StringBuilder errbuf);

	/**
	 * Checks if the current platform has support for pcap_create,
	 * pcap_set_buffer_size, pcap_set_snaplen, pcap_set_timeout,
	 * pcap_setdirection, pcap_set_promisc, pcap_can_rfmon, pcap_set_rfmon,
	 * pcap_activate calls which are only availabled on platforms that support
	 * minimum libpcap version 1.0.0.
	 * 
	 * @return true if the set of the above functions is supported on the platform
	 *         otherwise false.
	 */
	@SuppressWarnings("all")
	public static boolean isCreateSupported() {
		return IS_IMPLEMENTED;
	}

	/**
	 * Checks if the API implementation is contains actually implemented or are
	 * all function calls just stubs that throw UnsupportedOperationException even
	 * though appropriate libpcap may be installed on the system.
	 * 
	 * @return true if implementation is provided otherwise false if every
	 *         function will simply throw UnsupportedOperationException
	 */
	private native static boolean isImplemented();

	/**
	 * Loads the native library. If the library has already been loaded, this
	 * method does nothing. If a library load was previously attempted and failed,
	 * this method does nothing.
	 */
	public static void load() {
		/*
		 * Empty - just triggers the static initializer which loads the library once
		 */
	}

	/**
	 * Don't let anyone instantiate it but createMethod.
	 */
	private Pcap100() {
		// empty
	}

	/**
	 * Is used to activate a packet capture handle to look at packets on the
	 * network, with the options that were set on the handle being in effect.
	 * 
	 * @return returns 0 on success without warnings,
	 *         {@link #WARNING_PROMISC_NOT_SUP} on success on a device that
	 *         doesn't support promiscuous mode if promiscuous mode was requested,
	 *         {@link #WARNING} on success with any other warning,
	 *         {@link #ERROR_ACTIVATED} if the handle has already been activated,
	 *         {@link #ERROR_NO_SUCH_DEVICE} if the capture source specified when
	 *         the handle was created doesn't exist, {@link #ERROR_PERM_DENIED} if
	 *         the process doesn't have permission to open the capture source,
	 *         {@link #ERROR_RFMON_NOTSUP} if monitor mode was specified but the
	 *         capture source doesn't support monitor mode,
	 *         {@link #ERROR_IFACE_NOT_UP} if the capture source is not up, and
	 *         {@link #ERROR} if another error occurred.
	 *         <p>
	 *         If {@link #WARNING} or {@link #ERROR} is returned,
	 *         {@link #getErr()} gets the message describing the warning or error.
	 *         If {@link #WARNING_PROMISC_NOT_SUP}, {@link #ERROR_NO_SUCH_DEVICE},
	 *         or {@link #ERROR_PERM_DENIED} is returned, {@link #getErr()} gets
	 *         the message giving additional details about the problem that might
	 *         be useful for debugging the problem if it's unexpected.
	 *         </p>
	 * @since 1.4
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@SuppressWarnings("all")
	public native int activate();

	/**
	 * Check whether monitor mode can be set for a not-yet-activated capture
	 * handle. Checks whether monitor mode could be set on a capture handle when
	 * the handle is activated.
	 * 
	 * @return returns 0 if monitor mode could not be set, 1 if monitor mode could
	 *         be set, {@link #ERROR_NO_SUCH_DEVICE} if the device specified when
	 *         the handle was created doesn't exist, {@link #ERROR_ACTIVATED} if
	 *         called on a capture handle that has been activated, or
	 *         {@link #ERROR} if an error occurred. If {@link #ERROR} is returned,
	 *         {@link #getErr()} gets the error text.
	 * @since 1.4
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@SuppressWarnings("all")
	public native int canSetRfmon();

	/**
	 * sets the buffer size that will be used on a capture handle when the handle
	 * is activated to buffer_size, which is in units of bytes.
	 * 
	 * @param size
	 *          size that will be used on a capture handle
	 * @return 0 on success or {@link #ERROR_ACTIVATED} if called on a capture
	 *         handle that has been activated.
	 * @since 1.4
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@SuppressWarnings("all")
	public native int setBufferSize(long size);

	/**
	 * Set the direction for which packets will be captured. The method
	 * <code>setDirection()</code> is used to specify a direction that packets
	 * will be captured. dir is one of the constants {@link #IN}, {@link #OUT} or
	 * {@link #INOUT}. {@link #IN} will only capture packets received by the
	 * device, {@link #OUT} will only capture packets sent by the device and
	 * {@link #INOUT} will capture packets received by or sent by the device.
	 * {@link #INOUT} is the default setting if this function is not called.
	 * <p>
	 * pcap_setdirection() isn't necessarily fully supported on all platforms;
	 * some platforms might return an error for all values, and some other
	 * platforms might not support {@link #OUT}.
	 * </p>
	 * <p>
	 * This operation is not supported if a "savefile" is being read.
	 * </p>
	 * <p>
	 * This method is private since native method uses specific pcap_direction_t
	 * enum structure to make the call and java int doesn't provide the proper
	 * typesafety. This is why we use a public method first requiring a java enum
	 * type, and convert that to appropriate native integer value.
	 * </p>
	 * 
	 * @param dir
	 *          direction that packets will be captured.
	 * @return returns 0 on success and {@link #ERROR} on failure. If
	 *         {@link #ERROR} is returned, {@link #getErr()} gets the error text.
	 * @since 1.4
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public native int setDirection(int dir);

	/**
	 * Set promiscuous mode for a not-yet-activated capture handle. Sets whether
	 * promiscuous mode should be set on a capture handle when the handle is
	 * activated. If promisc is non-zero, promiscuous mode will be set, otherwise
	 * it will not be set.
	 * 
	 * @param promisc
	 *          if promisc is non-zero, promiscuous mode will be set, otherwise it
	 *          will not be set
	 * @return returns 0 on success or {@link #ERROR_ACTIVATED} if called on a
	 *         capture handle that has been activated
	 * @since 1.4
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@SuppressWarnings("all")
	public native int setPromisc(int promisc);

	/**
	 * Set monitor mode for a not-yet-activated capture handle.
	 * 
	 * @param rfmon
	 *          sets whether monitor mode should be set on a capture handle when
	 *          the handle is activated. If rfmon is non-zero, monitor mode will
	 *          be set, otherwise it will not be set.
	 * @return returns 0 on success or {@link #ERROR_ACTIVATED} if called on a
	 *         capture handle that has been activated
	 * @since 1.4
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@SuppressWarnings("all")
	public native int setRfmon(int rfmon);

	/**
	 * Set the snapshot length for a not-yet-activated capture handle. Sets the
	 * snapshot length to be used on a capture handle when the handle is activated
	 * to snaplen.
	 * 
	 * @param snaplen
	 *          snapshot length
	 * @return returns 0 on success or {@link #ERROR_ACTIVATED} if called on a
	 *         capture handle that has been activated
	 * @since 1.4
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@SuppressWarnings("all")
	public native int setSnaplen(int snaplen);

	/**
	 * Set the read timeout for a not-yet-activated capture handle. Sets the read
	 * timeout that will be used on a capture handle when the handle is activated
	 * to timeout, which is in units of milliseconds.
	 * 
	 * @param timeout
	 *          timeout value in milli seconds
	 * @return returns 0 on success or {@link #ERROR_ACTIVATED} if called on a
	 *         capture handle that has been activated
	 * @since 1.4
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	@SuppressWarnings("all")
	public native int setTimeout(int timeout);
}
