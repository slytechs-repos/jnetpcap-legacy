package org.jnetpcap.packet.annotate;

import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.JProtocol.Suite;

/**
 * Standard protocol suite names.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public enum ProtocolSuite implements Suite {
	APPLICATION,
	TCP_IP,
	SECURITY,
	VPN,
	MOBILE,
	NETWORK,
	WIRELESS,
	VOIP,
	LAN,
	MAN,
	WAN,
	SAN,
	ISO,
	SS7,
	CISCO,
	IBM,
	MICROSOFT,
	NOVELL,
	APPLE,
	HP,
	SUN,
	OTHER,
}