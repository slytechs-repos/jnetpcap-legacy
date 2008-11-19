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
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JNumber;
import org.jnetpcap.nio.JStruct;

/**
 * Provides access to various unix operating system related functions.
 * <p>
 * The class also provides a number of UNIX style constants that can be passed
 * into various unix calls. The numerical values of each constant are jNetPcap
 * stub values that are different from any underlying unix native values. The
 * stub values are mapped onto the underlying operating system call. Also
 * passing in numerical integers into the unix calls, values that are valid UNIX
 * values, will result in errors and/or exceptions as they are not what is
 * expected by the unix calls. The constants represent the various UNIX
 * functions that have been tested and are implemented in jNetPcap unix
 * extension. The stub constants that do not have a mapping are passed through
 * to the native unix calls untranslated.
 * </p>
 * 
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class UnixOs {

	/**
	 * Base class for all PEERED IF IOCTL call and their structures. Every ifreq
	 * begins with an interface name. One important thing to notice about this
	 * structure and class is that most of the fields are UNIONs. Therefore
	 * outside of the name() methods, one one getter method will be
	 * available/correct depending on which ioctl() call was made. No exceptions
	 * are thrown for incorrect lookup of a value of the peered structure.
	 * 
	 * <pre>
	 * ifreq structure:
	 * 
	 * struct ifreq
	 *  {
	 *  # define IFHWADDRLEN    6
	 *  # define IFNAMSIZ   IF_NAMESIZE
	 *  union
	 *  {
	 *  char ifrn_name[IFNAMSIZ];   
	 *  } ifr_ifrn;
	 * 
	 *  union
	 *  {
	 *  struct sockaddr ifru_addr;
	 *  struct sockaddr ifru_dstaddr;
	 *  struct sockaddr ifru_broadaddr;
	 *  struct sockaddr ifru_netmask;
	 *  struct sockaddr ifru_hwaddr;
	 *  short int ifru_flags;
	 *  int ifru_ivalue;
	 *  int ifru_mtu;
	 *  struct ifmap ifru_map;
	 *  char ifru_slave[IFNAMSIZ];  
	 *  char ifru_newname[IFNAMSIZ];
	 *  __caddr_t ifru_data;
	 *  } ifr_ifru;
	 *  };
	 *  # define ifr_name   ifr_ifrn.ifrn_name  // interface name   
	 *  # define ifr_hwaddr ifr_ifru.ifru_hwaddr    // MAC address      
	 *  # define ifr_addr   ifr_ifru.ifru_addr  // address      
	 *  # define ifr_dstaddr    ifr_ifru.ifru_dstaddr   // other end of p-p lnk 
	 *  # define ifr_broadaddr  ifr_ifru.ifru_broadaddr // broadcast address    
	 *  # define ifr_netmask    ifr_ifru.ifru_netmask   // interface net mask   
	 *  # define ifr_flags  ifr_ifru.ifru_flags // flags        
	 *  # define ifr_metric ifr_ifru.ifru_ivalue    // metric       
	 *  # define ifr_mtu    ifr_ifru.ifru_mtu   // mtu          
	 *  # define ifr_map    ifr_ifru.ifru_map   // device map       
	 *  # define ifr_slave  ifr_ifru.ifru_slave // slave device     
	 *  # define ifr_data   ifr_ifru.ifru_data  // for use by interface 
	 *  # define ifr_ifindex    ifr_ifru.ifru_ivalue    // interface index      
	 *  # define ifr_bandwidth  ifr_ifru.ifru_ivalue    // link bandwidth   
	 *  # define ifr_qlen   ifr_ifru.ifru_ivalue    // queue length     
	 *  # define ifr_newname    ifr_ifru.ifru_newname   // New name    
	 * 
	 * </pre>
	 * 
	 * @since 1.2
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class IfReq
	    extends JStruct {

		/**
		 * Native structure name
		 */
		public static final String STRUCT_NAME = "if_req";

		static {
			initIDs();
		}

		private static native void initIDs();

		public IfReq() {
			super(STRUCT_NAME, sizeof());
		}

		private native static int sizeof();

		public final native String ifr_name();

		public final native void ifr_name(String name);

		public final native byte[] ifr_hwaddr();

		public final native int ifr_flags();

		public final native void ifr_flags(int flags);

		public final native int ifr_mtu();

		public final native void ifr_mtu(int mtu);
	}

	/**
	 * JMemory if_data structure.
	 * 
	 * <pre>
	 * typedef struct if_data {
	 * 				// generic interface information
	 * 	uchar_t	ifi_type;	// ethernet, tokenring, etc
	 * 	uchar_t	ifi_addrlen;	// media address length
	 * 	uchar_t	ifi_hdrlen;	// media header length
	 * 	uint_t	ifi_mtu;	// maximum transmission unit
	 * 	uint_t	ifi_metric;	// routing metric (external only)
	 * 	uint_t	ifi_baudrate;	// linespeed
	 * 				// volatile statistics
	 * 	uint_t	ifi_ipackets;	// packets received on interface
	 * 	uint_t	ifi_ierrors;	// input errors on interface
	 * 	uint_t	ifi_opackets;	// packets sent on interface
	 * 	uint_t	ifi_oerrors;	// output errors on interface
	 * 	uint_t	ifi_collisions;	// collisions on csma interfaces
	 * 	uint_t	ifi_ibytes;	// total number of octets received
	 * 	uint_t	ifi_obytes;	// total number of octets sent
	 * 	uint_t	ifi_imcasts;	// packets received via multicast
	 * 	uint_t	ifi_omcasts;	// packets sent via multicast
	 * 	uint_t	ifi_iqdrops;	// dropped on input, this interface
	 * 	uint_t	ifi_noproto;	// destined for unsupported protocol
	 * 	#if defined(_LP64)
	 * 	struct	timeval32 ifi_lastchange; // last updated 
	 * 	#else
	 * 	struct	timeval ifi_lastchange; // last updated
	 * 	#endif
	 * } if_data_t;
	 * 
	 * </pre>
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class IfData
	    extends JStruct {

		/**
		 * Native structure name
		 */
		public static final String STRUCT_NAME = "if_data";

		protected IfData() {
			super(STRUCT_NAME);
		}

		/**
		 * ethernet, tokenring, etc
		 * 
		 * @return gets value of the structure field
		 */
		public native int ifi_type();

		/**
		 * media address length
		 * 
		 * @return gets value of the structure field
		 */
		public native int ifi_addrlen();

		/**
		 * media header length
		 * 
		 * @return gets value of the structure field
		 */
		public native int ifi_hdrlen();

		/**
		 * maximum transmission unit
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_mtu();

		/**
		 * routing metric (external only)
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_metric();

		/**
		 * linespeed
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_baudrate();

		/**
		 * packets received on interface
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_ipackets();

		/**
		 * input errors on interface
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_ierrors();

		/**
		 * packets sent on interface
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_opackets();

		/**
		 * output errors on interface
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_oerrors();

		/**
		 * collisions on csma interfaces
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_collisions();

		/**
		 * total number of octets received
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_ibytes();

		/**
		 * total number of octets sent
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_obytes();

		/**
		 * packets received via multicast
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_imcasts();

		/**
		 * packets sent via multicast
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_omcasts();

		/**
		 * dropped on input, this interface
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_iqdrops();

		/**
		 * destined for unsupported protocol
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_noproto();

		/**
		 * last updated
		 * 
		 * @return gets value of the structure field
		 */
		public native long ifi_lastchange();
	}

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
	 * @return result code
	 */
	public static native int socket(int domain, int type, int protocol);

	/**
	 * a unix ioctl call
	 * 
	 * @param d
	 * @param request
	 * @param data
	 * @return result code
	 */
	public static native int ioctl(int d, int request, Object data);

	/**
	 * a unix ioctl call
	 * 
	 * @param d
	 * @param request
	 * @param data
	 * @return result code
	 */
	public static native int ioctl(int d, int request, int data);

	/**
	 * a unix ioctl call
	 * 
	 * @param d
	 * @param request
	 * @param data
	 * @return result code
	 */
	public static native int ioctl(int d, int request, JNumber data);

	/**
	 * Returns the last error code returned by one of the unix functions
	 * 
	 * @return result code
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
	 * @return result code
	 */
	public static native int close(int d);

	/**
	 * Not instantiable
	 */
	private UnixOs() {
		// empty
	}

}
