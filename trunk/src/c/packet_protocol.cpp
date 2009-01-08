/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <jni.h>

#ifndef WIN32
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#endif /*WIN32*/

#include "packet_jscanner.h"
#include "packet_protocol.h"
#include "jnetpcap_utils.h"
#include "nio_jmemory.h"
#include "nio_jbuffer.h"
#include "org_jnetpcap_packet_JProtocol.h"
#include "export.h"

/*
 * Array of function pointers. These functions perform a per protocol scan
 * and return the next header. They also return the length of the header.
 * 
 * New protocols are added in the init_native_protocol() in this file.
 */
native_protocol_func_t native_protocols[MAX_ID_COUNT];
char *native_protocol_names[MAX_ID_COUNT];

void scan_not_implemented_yet(scan_t *scan) {
	
	sprintf(str_buf, "scanner (native or java) for protocol %s(%d) undefined",
			id2str(scan->id), scan->id);
	throwException(scan->env, ILLEGAL_STATE_EXCEPTION, str_buf);
}

/*
 * Scan Internet Control Message Protocol header
 */
void scan_icmp(scan_t *scan) {
	icmp_t *icmp = (icmp_t *)(scan->buf + scan->offset);
	
	switch (icmp->type) {
		
	case 3: // UNREACHABLE
	case 12: // PARAM PROBLEM
		scan->length = sizeof(icmp_t) + 4;
		scan->next_id = IP4_ID;
		break;
		
	case 0:  // Echo Reply
	case 8:  // Echo Request
	case 4: 
	case 5: 
	case 11:
	case 13: 
	case 14: 
	case 15: 
	case 16:
	default:
//		scan->length = scan->buf_len - scan->offset; 
		scan->length = 8; 
		break;
	}

}

/*
 * Scan Point to Point protocol
 */
void scan_ppp(scan_t *scan) {
	ppp_t *ppp = (ppp_t *)(scan->buf + scan->offset);
	scan->length = sizeof(ppp_t);
	
	switch (BIG_ENDIAN16(ppp->protocol)) {
	case 0x0021: scan->next_id = IP4_ID; break;
	}
}


/*
 * Scan Layer 2 Tunneling Protocol header
 */
void scan_l2tp(scan_t *scan) {
	l2tp_t *l2tp = (l2tp_t *)(scan->buf + scan->offset);
	scan->length = 6;
	if (l2tp->l == 1) {
		scan->length += 2;
	}
	if (l2tp->s == 1) {
		scan->length += 4;
	}
	if (l2tp->o == 1) {
		scan->length += 4;
	}

#ifdef DEBUG
	printf("scan() lL2TP_ID: b[0]=%d t=%d\n", 
			(int)*(scan->buf + scan->offset), l2tp->t);
	fflush(stdout);
#endif
	
	if (l2tp->t == 0) {
		scan->next_id = PPP_ID;
	}
}

/*
 * Scan IEEE 802.1q VLAN tagging header
 */
void scan_vlan(scan_t *scan) {
	vlan_t *vlan = (vlan_t *)(scan->buf + scan->offset);
	scan->length = sizeof(vlan_t);
	
	scan->next_id = lookup_ethertype(vlan->type);
	
	if (scan->next_id == PAYLOAD_ID) {
		scan->next_id = IEEE_802DOT2_ID;
	}
}

/*
 * Scan IEEE 802.2 or LLC2 header
 */
void scan_llc(scan_t *scan) {
	llc_t *llc = (llc_t *) (scan->buf + scan->offset);
	if (llc->control & 0x3 == 0x3) {
		scan->length = 3;
	} else {
		scan->length = 4;
	}

	switch (llc->dsap) {
	case 0xaa: scan->next_id = IEEE_SNAP_ID; break;
	}
}

/*
 * Scan IEEE SNAP header
 */
void scan_snap(scan_t *scan) {
	snap_t *snap = (snap_t *) (scan->buf + scan->offset);
	scan->length = 5;
	
	/*
	 * Set the flow key pair for SNAP.
	 * First, we check if SNAP has already been set by looking in the
	 * flow_key_t and checking if SNAP has previously been processed
	 */
	if ((scan->packet->pkt_flow_key.header_map & (1L << IEEE_SNAP_ID)) == 0) {
		scan->packet->pkt_flow_key.header_map |= (1L << IEEE_SNAP_ID);
		
		/*
		 * Ip4 always takes up pair[1]
		 * pair[1] is next protocol in on both sides of the pair
		 */
		scan->packet->pkt_flow_key.pair_count = 2;
		scan->packet->pkt_flow_key.forward_pair[1][0] = BIG_ENDIAN16(snap->pid);
		scan->packet->pkt_flow_key.forward_pair[1][1] = BIG_ENDIAN16(snap->pid);
		
		scan->packet->pkt_flow_key.id[1] = IEEE_SNAP_ID;
	}
	
	switch (snap->oui) {
	case 0: scan->next_id = lookup_ethertype(snap->pid); break;
	}
}

/*
 * Scan TCP header
 */
void scan_tcp(scan_t *scan) {
	

	tcp_t *tcp = (tcp_t *) (scan->buf + scan->offset);
	scan->length = tcp->doff * 4;
	
	
	/*
	 * Set the flow key pair for Tcp.
	 * First, we check if Tcp has already been set by looking in the
	 * flow_key_t and checking if Tcp has previously been processed
	 */
	if ((scan->packet->pkt_flow_key.header_map & (1L << TCP_ID)) == 0) {
		scan->packet->pkt_flow_key.header_map |= (1L << TCP_ID);
		
		/*
		 * Tcp takes up one pair
		 * pair[0] is tcp source and destination ports
		 */
		int count = scan->packet->pkt_flow_key.pair_count++;
		scan->packet->pkt_flow_key.forward_pair[count][0] = BIG_ENDIAN16(tcp->sport);
		scan->packet->pkt_flow_key.forward_pair[count][1] = BIG_ENDIAN16(tcp->dport);

		scan->packet->pkt_flow_key.id[count] = TCP_ID;

		scan->packet->pkt_flow_key.flags |= FLOW_KEY_FLAG_REVERSABLE_PAIRS;
		
//#define DEBUG
#ifdef DEBUG
	printf("scan_tcp(): count=%d map=0x%lx\n", 
			scan->packet->pkt_flow_key.pair_count,
			scan->packet->pkt_flow_key.header_map
			);
	fflush(stdout);
#endif
	}


}

/*
 * Scan UDP header
 */
void scan_udp(scan_t *scan) {
	udp_t *udp = (udp_t *) (scan->buf + scan->offset);
	scan->length = sizeof(udp_t);
	
	/*
	 * Set the flow key pair for Udp.
	 * First, we check if Udp has already been set by looking in the
	 * flow_key_t and checking if Udp has previously been processed
	 */
	if ((scan->packet->pkt_flow_key.header_map & (1L << UDP_ID)) == 0) {
		scan->packet->pkt_flow_key.header_map |= (1L << UDP_ID);
		
		/*
		 * Tcp takes up one pair
		 * pair[0] is tcp source and destination ports
		 */
		int count = scan->packet->pkt_flow_key.pair_count++;
		scan->packet->pkt_flow_key.forward_pair[count][0] = BIG_ENDIAN16(udp->sport);
		scan->packet->pkt_flow_key.forward_pair[count][1] = BIG_ENDIAN16(udp->dport);

		scan->packet->pkt_flow_key.id[count] = UDP_ID;
		
		scan->packet->pkt_flow_key.flags |= FLOW_KEY_FLAG_REVERSABLE_PAIRS;
	}
	
	switch (BIG_ENDIAN16(udp->dport)) {
	case 1701: scan->next_id = L2TP_ID;	break;
	}
}


/*
 * Payload is what's left over in the packet when no more header can be 
 * identified.
 */
void scan_payload(scan_t *scan) {
	scan->id = PAYLOAD_ID;
	scan->next_id = END_OF_HEADERS;
	scan->length = scan->buf_len - scan->offset;
}

/*
 * Scan IP version 6
 */
void scan_ip6(scan_t *scan) {
	ip6_t *ip6 = (ip6_t *)(scan->buf + scan->offset);
	scan->length = sizeof(ip6_t);
	uint8_t *buf = (uint8_t *)(scan->buf + scan->offset + sizeof(ip6_t));
	
	/*
	 * Set the flow key pair for Ip6.
	 * First, we check if Ip6 has already been set by looking in the
	 * flow_key_t and checking if it has been previously been processed
	 */
	if ((scan->packet->pkt_flow_key.header_map & (1L << IP6_ID)) == 0) {
		scan->packet->pkt_flow_key.header_map |= (1L << IP6_ID);
		
		/*
		 * Ip6 always takes up 2 pairs
		 * pair[0] is hash of addresses
		 * pair[1] is next protocol in on both sides of the pair
		 * 
		 */
		register uint32_t t;
		scan->packet->pkt_flow_key.pair_count = 2;
		
		t = *(uint32_t *)&ip6->ip6_src[0] ^ 
			*(uint32_t *)&ip6->ip6_src[4] ^
			*(uint32_t *)&ip6->ip6_src[8] ^
			*(uint32_t *)&ip6->ip6_src[12];
		scan->packet->pkt_flow_key.forward_pair[0][0] = t;
		
		t = *(uint32_t *)&ip6->ip6_dst[0] ^ 
			*(uint32_t *)&ip6->ip6_dst[4] ^
			*(uint32_t *)&ip6->ip6_dst[8] ^
			*(uint32_t *)&ip6->ip6_dst[12];
		scan->packet->pkt_flow_key.forward_pair[0][1] = t;
		
		scan->packet->pkt_flow_key.forward_pair[1][0] = ip6->ip6_nxt;
		scan->packet->pkt_flow_key.forward_pair[1][1] = ip6->ip6_nxt;
		
		scan->packet->pkt_flow_key.id[0] = IP6_ID;
		scan->packet->pkt_flow_key.id[1] = IP6_ID;
	}

	int type = ip6->ip6_nxt;
again:
	switch (type) {
	case 1: scan->next_id = ICMP_ID; break;
	case 4: scan->next_id = IP4_ID;  break;
	case 6: scan->next_id = TCP_ID;  break;
	case 17:scan->next_id = UDP_ID;  break;
	default:
		/* Skips over all option headers */
		type = (int) *(buf + 0); // Option type
		int len = (int) *(buf + 1); // Option length
		scan->length += len;
		buf += len;
		goto again;
	}
}


/*
 * Scan IP version 4
 */
void scan_ip4(scan_t *scan) {
	ip4_t *ip4 = (ip4_t *) (scan->buf + scan->offset);
	scan->length = ip4->ihl * 4;
	
	/*
	 * Set the flow key pair for Ip4.
	 * First, we check if Ip4 has already been set by looking in the
	 * flow_key_t and checking if Ip4 has previously been processed
	 */
	if ((scan->packet->pkt_flow_key.header_map & (1L << IP4_ID)) == 0) {
		scan->packet->pkt_flow_key.header_map |= (1L << IP4_ID);
		
		/*
		 * Ip4 always takes up pair[0] and pair[1]
		 * pair[0] is Ip addresses
		 * pair[1] is next protocol in on both sides of the pair
		 */
		scan->packet->pkt_flow_key.pair_count = 2;
		scan->packet->pkt_flow_key.forward_pair[0][0] = BIG_ENDIAN32(ip4->saddr);
		scan->packet->pkt_flow_key.forward_pair[0][1] = BIG_ENDIAN32(ip4->daddr);
		scan->packet->pkt_flow_key.forward_pair[1][0] = ip4->protocol;
		scan->packet->pkt_flow_key.forward_pair[1][1] = ip4->protocol;
		
		scan->packet->pkt_flow_key.id[0] = IP4_ID;
		scan->packet->pkt_flow_key.id[1] = IP4_ID;
	}

#ifdef DEBUG
	printf("scan_ip4(): type=%d frag_off=%d @ frag_off.pos=%X\n", 
			ip4->protocol, 
			BIG_ENDIAN16(ip4->frag_off) & IP4_FRAG_OFF_MASK, 
			(int)((char *)&ip4->frag_off - scan->buf));
	fflush(stdout);
#endif

	if ( (BIG_ENDIAN16(ip4->frag_off) & IP4_FRAG_OFF_MASK) != 0) {
		scan->next_id = PAYLOAD_ID;
		return;
	}

	switch (ip4->protocol) {
		case 1: scan->next_id = ICMP_ID; break;
		case 4: scan->next_id = IP4_ID;  break;
		case 6: scan->next_id = TCP_ID;  break;
		case 17:scan->next_id = UDP_ID;  break;
		case 115: scan->next_id = L2TP_ID; break;

		//			case 1: // ICMP
		//			case 2: // IGMP
		//			case 6: // TCP
		//			case 8: // EGP
		//			case 9: // IGRP
		//			case 17: // UDP
		//			case 41: // Ip6 over Ip4
		//			case 46: // RSVP
		//			case 47: // GRE
		//			case 58: // ICMPv6
		//			case 89: // OSPF
		//			case 90: // MOSPF
		//			case 97: // EtherIP
		//			case 132: // SCTP, Stream Control Transmission Protocol
		//			case 137: // MPLS in IP


	}	
}

/*
 * Scan IEEE 802.3 ethernet
 */
void scan_802dot3(scan_t *scan) {
	
	ethernet_t *eth = (ethernet_t *) (scan->buf + scan->offset);
	
	scan->length = sizeof(ethernet_t);
	


	if (BIG_ENDIAN16(eth->type) >= 0x600) { // We have an Ethernet frame
		scan->id      = ETHERNET_ID;
		scan->next_id = lookup_ethertype(eth->type);
		
		return;
		
	} else {
		scan->next_id = IEEE_802DOT2_ID; // LLC v2
	}
	
	/*
	 * Set the flow key pair for Ethernet.
	 * First, we check if Ethernet has already been set by looking in the
	 * flow_key_t and checking if it has been previously been processed
	 */
	if ((scan->packet->pkt_flow_key.header_map & (1L << IEEE_802DOT3_ID)) == 0) {
		scan->packet->pkt_flow_key.header_map |= (1L << IEEE_802DOT3_ID);
		
		/*
		 * Ethernet always takes up 2 pairs
		 * pair[0] is hash of addresses
		 * pair[1] is next protocol in on both sides of the pair
		 * 
		 * Our hash takes the last 4 bytes of address literally and XORs the
		 * remaining bytes with first 2 bytes
		 */
		register uint32_t t;
		scan->packet->pkt_flow_key.pair_count = 1;
		t = *(uint32_t *)&eth->dhost[2] ^ (*(uint16_t *)&eth->dhost[0]);
		scan->packet->pkt_flow_key.forward_pair[0][0] = t;
		t = *(uint32_t *)&eth->shost[2] ^ (*(uint16_t *)&eth->shost[0]);
		scan->packet->pkt_flow_key.forward_pair[0][1] = t;

		scan->packet->pkt_flow_key.id[0] = IEEE_802DOT3_ID;

	}

}


/*
 * Scan ethertype
 */
void scan_ethernet(scan_t *scan) {
	
	ethernet_t *eth = (ethernet_t *) (scan->buf + scan->offset);
	
	scan->length = sizeof(ethernet_t);
	
	/*
	 * Set the flow key pair for Ethernet.
	 * First, we check if Ethernet has already been set by looking in the
	 * flow_key_t and checking if it has been previously been processed
	 */
	if ((scan->packet->pkt_flow_key.header_map & (1L << ETHERNET_ID)) == 0) {
		scan->packet->pkt_flow_key.header_map |= (1L << ETHERNET_ID);
		
		/*
		 * Ethernet always takes up 2 pairs
		 * pair[0] is hash of addresses
		 * pair[1] is next protocol in on both sides of the pair
		 * 
		 * Our hash takes the last 4 bytes of address literally and XORs the
		 * remaining bytes with first 2 bytes
		 */
		register uint32_t t;
		scan->packet->pkt_flow_key.pair_count = 2;
		t = *(uint32_t *)&eth->dhost[2] ^ (*(uint16_t *)&eth->dhost[0]);
		scan->packet->pkt_flow_key.forward_pair[0][0] = t;
		t = *(uint32_t *)&eth->shost[2] ^ (*(uint16_t *)&eth->shost[0]);
		scan->packet->pkt_flow_key.forward_pair[0][1] = t;
		
		scan->packet->pkt_flow_key.forward_pair[1][0] = eth->type;
		scan->packet->pkt_flow_key.forward_pair[1][1] = eth->type;
		
		scan->packet->pkt_flow_key.id[0] = ETHERNET_ID;
		scan->packet->pkt_flow_key.id[1] = ETHERNET_ID;
	}


	if (BIG_ENDIAN16(eth->type) < 0x600) { // We have an IEEE 802.3 frame
		scan->id      = IEEE_802DOT3_ID;
		scan->next_id = IEEE_802DOT2_ID; // LLC v2
		
	} else {
		scan->next_id = lookup_ethertype(eth->type);
	}
}

int lookup_ethertype(uint16_t type) {
	switch (BIG_ENDIAN16(type)) {
	case 0x0800: return IP4_ID;
	case 0x86DD: return IP6_ID; 
	case 0x8100: return IEEE_802DOT1Q_ID;
	}
	
	return PAYLOAD_ID;
}



/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions. Private scan function
 * 
 * **************************************************************
 ****************************************************************/

void init_native_protocols() {
	
	// Builtin families
	native_protocols[PAYLOAD_ID]  = &scan_payload;
	
	// Datalink families
	native_protocols[ETHERNET_ID]      = &scan_ethernet;
	native_protocols[IEEE_802DOT2_ID]  = &scan_llc;
	native_protocols[IEEE_SNAP_ID]     = &scan_snap;
	native_protocols[IEEE_802DOT1Q_ID] = &scan_vlan;
	native_protocols[L2TP_ID]          = &scan_l2tp;
	native_protocols[PPP_ID]           = &scan_ppp;
	
	// TCP/IP families
	native_protocols[IP4_ID]      = &scan_ip4;
	native_protocols[IP6_ID]      = &scan_ip6;
	native_protocols[UDP_ID]      = &scan_udp;
	native_protocols[TCP_ID]      = &scan_tcp;
	native_protocols[ICMP_ID]     = &scan_icmp;
	
	native_protocols[IEEE_802DOT3_ID]      = &scan_not_implemented_yet;
	/*
	 * Now store the names of each header, used for debuggin purposes
	 */
	native_protocol_names[PAYLOAD_ID]       = "PAYLOAD";
	native_protocol_names[ETHERNET_ID]      = "ETHERNET";
	native_protocol_names[TCP_ID]           = "TCP";
	native_protocol_names[UDP_ID]           = "UDP";
	native_protocol_names[IEEE_802DOT3_ID]  = "IEEE_802DOT3";
	native_protocol_names[IEEE_802DOT2_ID]  = "IEEE_802DOT2";
	native_protocol_names[IEEE_SNAP_ID]     = "IEEE_SNAP";
	native_protocol_names[IP4_ID]           = "IP4";
	native_protocol_names[IP6_ID]           = "IP6";
	native_protocol_names[IEEE_802DOT1Q_ID] = "IEEE_802DOT1Q";
	native_protocol_names[L2TP_ID]          = "L2TP";
	native_protocol_names[PPP_ID]           = "PPP";
	native_protocol_names[ICMP_ID]          = "ICMP";
}

