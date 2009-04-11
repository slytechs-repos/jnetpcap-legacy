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

import org.jnetpcap.nio.JMemory;

/**
 * A Payload Link Provider Interface OSI implementation. This is a low level data
 * link service available on various unix systems. Operating systems such as Sun
 * Microsystems' Solaris, HP HP-UX, SGI Irix, IBM AIX and other utilize DLPI
 * standard for accessing low level networking functionality.
 * <p>
 * This class provides various DL functions and peers all the neccessary
 * structures to accomplish a subset of DLPI capabilities. Not all functions are
 * exposed but only a few ones which are not already provided by libpcap
 * functionality. One such function is to aquire MAC address for network
 * interface.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class Dlpi {

	/**
	 * Turn on promiscuous mode
	 */
	public final static int DL_PROMISCON_REQ = 0x1f;

	/**
	 * Turn off promiscuous mode
	 */
	public final static int DL_PROMISCOFF_REQ = 0x20;

	/**
	 * Request to get physical addr
	 */
	public final static int DL_PHYS_ADDR_REQ = 0x31;

	/**
	 * Return physical addr
	 */
	public final static int DL_PHYS_ADDR_ACK = 0x32;

	/**
	 * Request to get statistics
	 */
	public final static int DL_GET_STATISTICS_REQ = 0x34;

	/**
	 * Return statistics
	 */
	public final static int DL_GET_STATISTICS_ACK = 0x35;

	/**
	 * Checks if DLPI extension is available on this platform.
	 * 
	 * @return true if available otherwise false
	 */
	public native static boolean isSupported();

	/**
	 * Base structure for all DL requests and ACKs.
	 * 
	 * @author Mark Bednarczyk
	 * @author Sly Technologies, Inc.
	 */
	public static class DLBase
	    extends JMemory {
		public native int dl_primitive();

		public native void dl_primitive(int value);
	}

	public static class DLOkAck
	    extends DLBase {
		public native int dl_correct_primitive();
	}

	public static class DLErrorAck
	    extends DLBase {
		public native int dl_error_primitive();

		public native int dl_errno();

		public native int dl_unix_errno();
	}
	
	public static class DLPromisconReq extends DLBase {
		public native int dl_level();

		public native void dl_level(int value);		
	}

	public static class DLPromiscoffReq
	    extends DLBase {
		public native int dl_level();

		public native void dl_level(int value);
	}
	
	public static class DLPhysAddrReq extends DLBase {
		public native int dl_addr_type();
		public native void dl_addr_type(int type);
	}

	public static class DLPhysAddrAck
	    extends DLBase {
		public native int dl_addr_length();

		public native int dl_addr_offset();

		/**
		 * Returns the address as specified by the PhysAddrAck structure. The
		 * structure must be already filled in by a previous DLPI call. To prevent
		 * wild pointer access, this method checks if the structure has been filled
		 * in otherwise IllegalStateException will be thrown.
		 * 
		 * @return physical address byte array
		 */
		public native byte[] address() throws IllegalStateException;
	}
	
	public static class DLStatisticsReq extends DLBase {
		public DLStatisticsReq() {
			dl_primitive(DL_GET_STATISTICS_REQ);
		}		
	}
	
	public static class DLStatisticsAck extends DLBase {
		
		public DLStatisticsAck() {
			dl_primitive(DL_GET_STATISTICS_ACK);
		}
		
		public native int dl_stat_length();
		public native int dl_stat_offset();
		public native UnixOs.IfData data();
	}
}
