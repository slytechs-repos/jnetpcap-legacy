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
package org.jnetpcap.unix;

import org.jnetpcap.Pcap;

/**
 * Provides access to various unix operating system related functions.
 * 
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class UnixOs {
	private static final int IOCTL = 0x01000000;

	private static final int SOCKET_DOMAIN = 0x02000000;

	private static final int SOCKET_TYPE = 0x04000000;

	private static final int SOCKET_PROTOCOL = 0x08000000;

	/**
	 * IOCTL constant to get the network adapters HARDWARE address
	 * 
	 * @see IfReq
	 */
	public static final int SIOCGIFHWADDR = 0x0000001 | IOCTL;

	/**
	 * IOCTL constant to set the MTU
	 */
	public static final int SIOCSIFMTU = 0x0000002 | IOCTL;

	/**
	 * IOCTL constant to get the MTU
	 */
	public static final int SIOCGIFMTU = 0x0000004 | IOCTL;

	/**
	 * IOCTL constant to set the interface FLAGS
	 */
	public static final int SIOCSIFFLAGS = 0x0000008 | IOCTL;

	/**
	 * IOCTL constant to get the interface FLAGS
	 */
	public static final int SIOCGIFFLAGS = 0x0000010 | IOCTL;

	/**
	 * SOCKET domain constant - unix/local domain
	 */
	public static final int PF_UNIX = 0x0000001 | SOCKET_DOMAIN;

	/**
	 * SOCKET domain constant - IP v4 domain
	 */
	public static final int PF_INET = 0x0000002 | SOCKET_DOMAIN;

	/**
	 * SOCKET domain constant - IP v6 domain
	 */
	public static final int PF_INET6 = 0x0000004 | SOCKET_DOMAIN;

	/**
	 * SOCKET domain constant - IPX domain
	 */
	public static final int PF_IPX = 0x0000008 | SOCKET_DOMAIN;

	/**
	 * SOCKET domain constant - RAW packet interface domain
	 */
	public static final int PF_PACKET = 0x0000010 | SOCKET_DOMAIN;

	/**
	 * SOCKET type constant - stream type
	 */
	public static final int SOCK_STREAM = 0x0000001 | SOCKET_TYPE;

	/**
	 * SOCKET type constant - datagram type
	 */
	public static final int SOCK_DGRAM = 0x0000002 | SOCKET_TYPE;

	/**
	 * SOCKET type constant - raw type
	 */
	public static final int SOCK_RAW = 0x0000004 | SOCKET_TYPE;

	/**
	 * SOCKET type constant - packet type
	 */
	public static final int SOCK_PACKET = 0x0000008 | SOCKET_TYPE;

	/**
	 * SOCKET protocol constant - default protocol
	 */
	public static final int PROTOCOL_DEFAULT = 0x0000001 | SOCKET_PROTOCOL;

	/**
	 * SOCKET protocol constant - TCP protocol
	 */
	public static final int IPPROTO_TCP = 0x0000002 | SOCKET_PROTOCOL;

	static {
		Pcap.isInjectSupported(); // Force a library load
		initIDs();
	}

	/**
	 * Initialized JNI IDs
	 */
	private static native void initIDs();

	/**
	 * Checks if this is a UNIX platform that supports all of these methods
	 * 
	 * @return true it is supported, otherwise false
	 */
	public static native boolean isSupported();

	/**
	 * Translates a DECLARED constant to an OS specific counter part. These
	 * constants are translated for socket() and ioctl() calls.
	 * 
	 * @param constant
	 *          java constant
	 * @return native os constant
	 */
	public static native int translateConstant(int constant);

	/**
	 * Checks if a given operation using the supplied constant is supported. The
	 * OS is asked if this function is supported.
	 * 
	 * @param constant
	 *          constants which represents an ioctl operation, protocols, socket
	 *          domain, socket type
	 * @return true means it is supported, otherwise false
	 */
	public static boolean isSupported(int constant) {
		return translateConstant(constant) != -1;
	}

	/**
	 * A unix socket call
	 * 
	 * @param domain
	 * @param type
	 * @param protocol
	 * @return
	 */
	public static native int socket(int domain, int type, int protocol);

	/**
	 * a unix ioctl call
	 * 
	 * @param d
	 * @param request
	 * @param data
	 * @return
	 */
	public static native int ioctl(int d, int request, Object data);

	/**
	 * a unix ioctl call
	 * 
	 * @param d
	 * @param request
	 * @param data
	 * @return
	 */
	public static native int ioctl(int d, int request, int data);

	/**
	 * Returns the last error code returned by one of the unix functions
	 * 
	 * @return
	 */
	public static native int errno();

	/**
	 * The strerror() function returns a string describing the error code passed
	 * in the argument errnum, possibly using the LC_MESSAGES part of the current
	 * locale to select the appropriate language.
	 * 
	 * @param errnum
	 *          error number returned from a unix call
	 * @return error message
	 */
	public static native String strerror(int errnum);

	/**
	 * Closes a socket given a descriptor
	 * 
	 * @param d
	 * @return
	 */
	public static native int close(int d);

	/**
	 * Not instantiable
	 */
	private UnixOs() {
		// empty
	}

}
