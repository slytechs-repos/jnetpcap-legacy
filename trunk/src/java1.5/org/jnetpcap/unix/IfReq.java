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

import org.jnetpcap.Peered;

/**
 * Base class for all PEERED IF IOCTL call and their structures. Every ifreq
 * begins with an interface name. One important thing to notice about this
 * structure and class is that most of the fields are UNIONs. Therefore outside
 * of the name() methods, one one getter method will be available/correct
 * depending on which ioctl() call was made. No exceptions are thrown for
 * incorrect lookup of a value of the peered structure.
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
public final class IfReq
    extends Peered {

	static {
		initIDs();
	}

	private static native void initIDs();

	public IfReq() {
		super(sizeof());
	}

	private static native int sizeof();

	public final native String ifr_name();

	public final native void ifr_name(String name);

	public final native byte[] ifr_hwaddr();

	public final native int ifr_flags();

	public final native void ifr_flags(int flags);

	public final native int ifr_mtu();

	public final native void ifr_mtu(int mtu);
}
