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
package org.jnetpcap.ms;

import org.jnetpcap.nio.JStruct;

/**
 * The MIB_IFROW structure stores information about a particular interface.
 * 
 * <pre>
 * typedef struct _MIB_IFROW {
 *   WCHAR wszName[MAX_INTERFACE_NAME_LEN];
 *   DWORD dwIndex;
 *   DWORD dwType;
 *   DWORD dwMtu;
 *   DWORD dwSpeed;
 *   DWORD dwPhysAddrLen;
 *   BYTE bPhysAddr[MAXLEN_PHYSADDR];
 *   DWORD dwAdminStatus;
 *   DWORD dwOperStatus;
 *   DWORD dwLastChange;
 *   DWORD dwInOctets;
 *   DWORD dwInUcastPkts;
 *   DWORD dwInNUcastPkts;
 *   DWORD dwInDiscards;
 *   DWORD dwInErrors;
 *   DWORD dwInUnknownProtos;
 *   DWORD dwOutOctets;
 *   DWORD dwOutUcastPkts;
 *   DWORD dwOutNUcastPkts;
 *   DWORD dwOutDiscards;
 *   DWORD dwOutErrors;
 *   DWORD dwOutQLen;
 *   DWORD dwDescrLen;
 *   BYTE bDescr[MAXLEN_IFDESCR];
 * } MIB_IFROW,  *PMIB_IFROW;
 * </pre>
 * 
 * @see MSIpHelper#getIfEntry(MSMibIfRow)
 * @since 1.2
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class MSMibIfRow
    extends JStruct {

	/**
	 * WAN adapter that is connected to a remote peer.
	 */
	public static final int IF_OPER_STATUS_CONNECTED = 1;

	/**
	 * WAN adapter that is in the process of connecting.
	 */
	public static final int IF_OPER_STATUS_CONNECTING = 1;

	/**
	 * For LAN adapters: network cable disconnected. For WAN adapters: no carrier.
	 */
	public static final int IF_OPER_STATUS_DISCONNECTED = 1;

	/**
	 * LAN adapter has been disabled, for example because of an address conflict.
	 */
	public static final int IF_OPER_STATUS_NON_OPERATIONAL = 1;

	/**
	 * Default status for LAN adapters
	 */
	public static final int IF_OPER_STATUS_OPERATIONAL = 1;

	/**
	 * WAN adapter that is not connected.
	 */
	public static final int IF_OPER_STATUS_UNREACHABLE = 1;

	/**
	 * An ATM network interface.
	 */
	public final static int IF_TYPE_ATM = 37;

	/**
	 * An Ethernet network interface.
	 */
	public final static int IF_TYPE_ETHERNET_CSMACD = 6;

	/**
	 * An IEEE 1394 (Firewire) high performance serial bus network interface.
	 */
	public final static int IF_TYPE_IEEE1394 = 144;

	/**
	 * An IEEE 802.11 wireless network interface.
	 */
	public final static int IF_TYPE_IEEE80211 = 71;

	/**
	 * A token ring network interface.
	 */
	public final static int IF_TYPE_IOS88025_TOKENRING = 9;

	/**
	 * A software loopback network interface.
	 */
	public final static int IF_TYPE_LOOPBACK = 24;

	/**
	 * Some other type of network interface.
	 */
	public final static int IF_TYPE_OTHER = 1;

	/**
	 * A PPP network interface.
	 */
	public final static int IF_TYPE_PPP = 23;

	/**
	 * A tunnel type encapsulation network interface.
	 */
	public final static int IF_TYPE_TUNNEL = 131;

	/**
	 * Native structure name
	 */
	public static final String STRUCT_NAME = "MIB_IFROW";

	/**
	 * Checks if this extension is supported on this platform. This method does
	 * not throw any exceptions and is safe to use on any platform.
	 * 
	 * @return true means it is supported, otherwise false
	 */
	public static boolean isSupported() {
		return MSIpHelper.isSupported();
	}

	/**
	 * Native method which returns the size of this constant structure.
	 * 
	 * @return size of the peered structure in byte as returned by C statement
	 *         sizeof(struct MibIfRow)
	 */
	public native static int sizeof();

	/**
	 * Allocates peered struct MibIfRow of default size
	 */
	public MSMibIfRow() {
		super(STRUCT_NAME, sizeof());
	}

	/**
	 * A description of the interface.
	 * <p>
	 * <b>Note:</b> According to Microsoft this field is usually blank
	 * </p>
	 * 
	 * @return a description of the interface
	 */
	public native String bDescr();

	/**
	 * The physical address of the adapter for this interface.
	 * 
	 * @return hardware address array
	 */
	public native byte[] bPhysAddr();

	/**
	 * The interface is administratively enabled or disabled.
	 * 
	 * @return status of interface
	 */
	public native int dwAdminStatus();

	/**
	 * The length, in bytes, of the bDescr member.
	 * 
	 * @return length of bDescr member
	 */
	public native int dwDescrLen();

	/**
	 * The index that identifies the interface. This index value may change when a
	 * network adapter is disabled and then enabled, and should not be considered
	 * persistent.
	 * 
	 * @return index
	 */
	public native int dwIndex();

	/**
	 * Sets the index value in the peered structure
	 * 
	 * @param value
	 *          value to set
	 */
	public native void dwIndex(int value);

	/**
	 * The number of incoming packets that were discarded even though they did not
	 * have errors.
	 * 
	 * @return number of packets
	 */
	public native int dwInDiscards();

	/**
	 * The number of incoming packets that were discarded because of errors.
	 * 
	 * @return number of packets
	 */
	public native int dwInErrors();

	/**
	 * The number of non-unicast packets received through this interface.
	 * Broadcast and multicast packets are included.
	 * 
	 * @return number of packets
	 */
	public native int dwInNUcastPkts();

	/**
	 * The number of unicast packets received through this interface.
	 * 
	 * @return number of packets
	 */
	public native int dwInUcastPkts();

	/**
	 * The number of incoming packets that were discarded because the protocol was
	 * unknown.
	 * 
	 * @return number of packets
	 */
	public native int dwInUnknownProtos();

	/**
	 * The length of time, in hundredths of seconds (10^-2 sec), starting from the
	 * last computer restart, when the interface entered its current operational
	 * state. This value rolls over after 2^32 hundredths of a second. The
	 * dwLastChange member is not currently supported by NDIS. On Windows Vista
	 * and later, NDIS returns zero for this member. On earlier versions of
	 * Windows, an arbitrary value is returned in this member for the interfaces
	 * supported by NDIS. For interfaces supported by other interface providers,
	 * they might return an appropriate value. dwInOctets
	 * 
	 * @return length of time since restart when the interface entered its current
	 *         OP state
	 */
	public native int dwLastChange();

	/**
	 * The Maximum Transmission Unit (MTU) size in bytes.
	 * 
	 * @return mtu size in bytes
	 */
	public native int dwMtu();

	/**
	 * The operational status of the interface.
	 * 
	 * @return status of interface
	 */
	public native int dwOperStatus();

	/**
	 * The number of outgoing packets that were discarded even though they did not
	 * have errors.
	 * 
	 * @return number of packets
	 */
	public native int dwOutDiscards();

	/**
	 * The number of outgoing packets that were discarded because of errors.
	 * 
	 * @return number of packets
	 */
	public native int dwOutErrors();

	/**
	 * The number of non-unicast packets sent through this interface. Broadcast
	 * and multicast packets are included.
	 * 
	 * @return number of packets
	 */
	public native int dwOutNUcastPkts();

	/**
	 * The number of octets of data sent through this interface.
	 * 
	 * @return number of octets
	 */
	public native int dwOutOctets();

	/**
	 * The transmit queue length. This field is not currently used.
	 * 
	 * @return length of queue
	 */
	public native int dwOutQLen();

	/**
	 * The number of unicast packets sent through this interface.
	 * 
	 * @return number of packets
	 */
	public native int dwOutUcastPkts();

	/**
	 * The length, in bytes, of the physical address specified by the bPhysAddr
	 * member.
	 * 
	 * @return length of hardware address
	 */
	public native int dwPhysAddrLen();

	/**
	 * The speed of the interface in bits per second.
	 * 
	 * @return speed of interface
	 */
	public native int dwSpeed();

	/**
	 * The interface type as defined by the Internet Assigned Names Authority
	 * (IANA). For more information, see
	 * http://www.iana.org/assignments/ianaiftype-mib. Common values for the
	 * interface type are defined as constants in this class.
	 * 
	 * @return interface type
	 */
	public native int dwType();

	/**
	 * string that contains the name of the interface.
	 * <p>
	 * <b>Note:</b> According to Microsoft this field is usually blank
	 * </p>
	 * 
	 * @return name
	 */
	public native String wszName();
}
