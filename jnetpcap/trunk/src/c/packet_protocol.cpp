/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 * 
 * This file contains functions for dissecting and scanning packets. 
 * First  it defines some global tables that are used to initialize 
 * packet_scanner. Second, two types of functions are defined in this file,
 * where the first scan_* is used as a scanner (wireshark term dissector),
 * and the second as validator of the header in validate_* function.
 * 
 * The scanner function is a void function which returns its findings
 * by modifying the scan_t structure passed to it. The most critical
 * parameter being scan.length which holds the length of the header. 
 * 
 * The validator function is completely passive and does not modify scan_t
 * structure passed to it. The return value determines if validation 
 * succeeded or failed. The validator function (validate_*) returns either
 * the numerical header ID of the header its validating if its a valid 
 * header, or the constant INVALID. A table lookup is provided using 2 
 * functions validate and validate_next. The validate function assumes the
 * header is at the current offset, while validate_next validates the
 * header at offset + length + gap (gap is another property that determines
 * the number of bytes between the header and its payload, a padding of 
 * sorts.) The result from validate_next can be directly assigned to
 * scan.next_id is typically how this function was designed to work. 
 * The INVALID constant is mapped to PAYLOAD_ID constant which is a valid
 * catch-all header when validation failes.
 * 
 * Validator function (validate_*) is also used as a heuristic determinant
 * for the next possible header. The main scanner loop, using 
 * native_heuristics table (defined in this file), maintains a list of 
 * validate functions as a heuristic check if port/type number lookup for 
 * next header in packet fails.
 * 
 * Note the function signature differences between a scan_* and validate_*
 * functions:
 *  typedef void (*native_protocol_func_t)(scan_t *scan);
 *  typedef int (*native_validate_func_t)(scan_t *scan);
 * 
 * Lastly the file contains a init_native_protocols function which is
 * called only once during initialization phase. This is where all the
 * defined scan_* and validate_* functions are referenced for storage in 
 * the lookup tables. Also a numerical ID to text lookup table is uset up
 * so that numerical header IDs can be mapped to text. This table is only
 * used for debug purposes, but none the less it is an important table 
 * and any new protocol added must be defined in it.
 * 
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
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
#include "org_jnetpcap_protocol_JProtocol.h"
#include "export.h"

/*
 * Array of function pointers. These functions perform a per protocol scan
 * and return the next header. They also return the length of the header.
 * 
 * New protocols are added in the init_native_protocol() in this file.
 */
native_protocol_func_t native_protocols[MAX_ID_COUNT];
native_validate_func_t native_heuristics[MAX_ID_COUNT][MAX_ID_COUNT];
native_validate_func_t validate_table[MAX_ID_COUNT];

char *native_protocol_names[MAX_ID_COUNT];

void scan_not_implemented_yet(scan_t *scan) {
	
	sprintf(str_buf, "scanner (native or java) for protocol %s(%d) undefined",
			id2str(scan->id), scan->id);
	throwException(scan->env, ILLEGAL_STATE_EXCEPTION, str_buf);
}


/*
 * Scan SLL (Linux Cooked Capture) header
 */
void scan_sll(scan_t *scan) {
	register sll_t *sll = (sll_t *)(scan->buf + scan->offset);
	scan->length = SLL_LEN;
	
	switch(BIG_ENDIAN16(sll->sll_protocol)) {
	case 0x800:	scan->next_id = validate_next(IP4_ID, scan);	return;
	}
	
//	printf("scan_sll() next_id=%d\n", scan->next_id);
//	fflush(stdout);
}


/**
 * validate_rtp validates values for RTP header at current scan.offset.
 * 
 * DO NOT CHANGE any scan properties. This is a completely passive method, only
 * the return value determines if validation passed or not. Return either
 * constant INVALID or header ID constant.
 */
int validate_rtp(scan_t *scan) {
	register rtp_t *rtp = (rtp_t *)(scan->buf + scan->offset);
	
	
	if (rtp->rtp_ver != 2 || 
			rtp->rtp_cc > 15 || 
			rtp->rtp_type > 25 || 
			rtp->rtp_seq == 0 || 
			rtp->rtp_ts == 0 ||
			rtp->rtp_ssrc == 0
			) {
		
#ifdef DEBUG
		printf("validate_rtp() INVALID 1 offset=%d raw=0x%x\n", scan->offset,
				(int) (*(uint8_t *)rtp));
		printf("validate_rtp() "
				"v=%d, p=%d, x=%d, cc=%d, m=%d, pt=%d seq=%d, ts=%d\n",
				(int) rtp->rtp_ver,
				(int) rtp->rtp_pad,
				(int) rtp->rtp_ext,
				(int) rtp->rtp_cc,
				(int) rtp->rtp_marker,
				(int) rtp->rtp_type,
				(int) BIG_ENDIAN16(rtp->rtp_seq),
				(int) BIG_ENDIAN32(rtp->rtp_ts)
				);
		fflush(stdout);
#endif	
	
		return INVALID;
	}
	
	uint32_t *c = (uint32_t *)(scan->buf + scan->offset + RTP_LENGTH);
	for (int i = 0; i < rtp->rtp_cc; i ++) {
		if (c[i] == 0) {
			
#ifdef DEBUG
			printf("validate_rtp() INVALID 2\n"); fflush(stdout);
#endif
			
			return INVALID;
		}
	}
	
	if (rtp->rtp_ext) {
		rtpx_t * rtpx = (rtpx_t *)(scan->buf + scan->offset + scan->length);
		
		if (BIG_ENDIAN16(rtpx->rtpx_len) > (1500 / 4)) {
			printf("validate_rtp() INVALID 3\n"); fflush(stdout);
			return INVALID;
		}
	}
	
#ifdef DEBUG
	printf("validate_rtp() OK\n"); fflush(stdout);
#endif
	
	return RTP_ID;
}

/*
 * Scan Session Data Protocol header
 */
void scan_rtp(scan_t *scan) {
	register rtp_t *rtp = (rtp_t *)(scan->buf + scan->offset);
	
	scan->length += RTP_LENGTH + rtp->rtp_cc * 4;
	
	/*
	 * Check for extension. We don't care here what it is, just want to add up
	 * all the lengths
	 */
	if (rtp->rtp_ext) {
		rtpx_t * rtpx = (rtpx_t *)(scan->buf + scan->offset + scan->length);
		
		scan->length += (BIG_ENDIAN16(rtpx->rtpx_len) * 4) + RTPX_LENGTH;
	}
	
	/* If RTP payload is padded, the last byte contains number of pad bytes
	 * used.
	 */
	if (rtp->rtp_pad) {
		scan->hdr_postfix = scan->buf[scan->buf_len -1];
	}

/*************************
	switch (rtp->type)) {
	case 0:  // PCMU 8K
	case 1:  // 1016 8K
	case 2:  // G721 8K
	case 3:  // GSM 8K
	case 4:  // G723 8K
	case 5:  // DVI4 8K
	case 6:  // DVI4 16K
	case 7:  // LPC 8K
	case 8:  // PCMA 8K
	case 9:  // G722 8K
	case 10: // L16 44K 2CH
	case 11: // l16 44K 1CH
	case 12: // QCELP 8K
	case 13: // CN 8K
	case 14: // MPA 90K
	case 15: // G728 8K
	case 16: // DVI4 11K
	case 17: // DVI4 22K
	case 18: // G729 8K
	case 25: // CellB 90K
	case 26: // JPEG 90K
	case 28: // NV 90K
	case 31: // H261 90K
	case 32: // MPV 90K
	case 33: // MP2T 90K
	case 34: // H263 90K
	}
****************/

}


/*
 * Scan Session Data Protocol header
 */
void scan_sdp(scan_t *scan) {
	register char *sdp = (char *)(scan->buf + scan->offset);
	
	scan->length = scan->buf_len - scan->offset;
}


/*
 * Scan Session Initiation Protocol header
 */
void scan_sip(scan_t *scan) {
	register char *sip = (char *)(scan->buf + scan->offset);
	packet_state_t *packet = scan->packet;
	
	/*
	 * To calculate length we need to take it from ip header - tcp header
	 */
	char *buf = scan->buf;
	header_t tcph = packet->pkt_headers[packet->pkt_header_count -1];
	
	register int size = tcph.hdr_payload;
		
	scan->length = size;
		
#ifdef DEBUG
	char b[32];
	b[0] = '\0';
	b[31] = '\0';
	strncpy(b, http, (size <= 31)? size : 31);
		
	if (size < 10)
	printf("scan_sip(): #%d INVALID size=%d sip=%s\n", 
			(int) scan->packet->pkt_frame_num, size, b);
#endif 

	char * content_type = NULL;
	/*
	 * We could use strstr(), but for efficiency and since we need to lookup
	 * multiple sub-strings in the text header, we use our own loop.
	 */
	for (int i = 0; i < size; i ++){
		if ((sip[i] == 'c' || sip[i] == 'C') && 
				strncmp(&sip[i], "Content-Type:", 13)) {
			content_type = &sip[i + 13];
		}
			
		if (sip[i] == '\r' && sip[i + 1] == '\n' 
			&& sip[i + 2] == '\r' && sip[i + 3] == '\n') {
				
			scan->length = i + 4;
			break;
		}
	}
	
	if (content_type == NULL) {
		scan->next_id = PAYLOAD_ID;
		return;
	}
	
	char *end = &sip[scan->length - 15];
	
	/* Skip whitespace and prevent runaway search */
	while (isspace(*content_type) && (content_type < end)) {
		content_type ++;
	}
	
	if (strncmp(content_type, "application/sdp", 15)) {
		scan->next_id = validate_next(SDP_ID, scan);	return;
	}
		
	return;
}

/**
 * validate_sip validates values for SIP header at current scan.offset.
 * 
 * DO NOT CHANGE any scan properties. This is a completely passive method, only
 * the return value determines if validation passed or not. Return either
 * constant INVALID or header ID constant.
 */
int validate_sip(scan_t *scan) {
	char *sip = (char *)(scan->buf + scan->offset);
	packet_state_t *packet = scan->packet;
	
	/*
	 * To calculate length we need to take it from ip header - tcp header
	 */
	char *buf = scan->buf;
	header_t tcph = packet->pkt_headers[packet->pkt_header_count -1];
	
	int size = tcph.hdr_payload;
	
	/* First sanity check if we have printable chars */
	if (size < 5 || 
		(isprint(sip[0]) && isprint(sip[1]) && isprint(sip[2])) == FALSE) {
		
#ifdef DEBUG
		char b[32];
		b[0] = '\0';
		b[31] = '\0';
		strncpy(b, sip, (size <= 31)? size : 31);
		
		printf("validate_sip(): UNMATCHED size=%d sip=%s\n", size, b);
#endif 
		return INVALID;
	}
	
	if (	/* SIP Response */
			strncmp(sip, "SIP", 3) == 0 ||
			
			/* SIP Requests */
			strncmp(sip, "REGISTER", 8) == 0 || 
			strncmp(sip, "INVITE", 6) == 0 || 
			strncmp(sip, "ACK", 3) == 0 || 
			strncmp(sip, "CANCEL", 6) == 0 || 
			strncmp(sip, "BYE", 3) == 0 || 
			strncmp(sip, "OPTIONS", 7) == 0 ) {
		
#ifndef DEBUG
		char b[32];
		b[0] = '\0';
		b[31] = '\0';
		strncpy(b, sip, (size <= 31)? size : 31);
		
		if (size < 10)
		printf("validate_sip(): #%d INVALID size=%d sip=%s\n", 
				(int) scan->packet->pkt_frame_num, size, b);
#endif 

	} 
	
	return SIP_ID;
}



/*
 * Scan Hyper Text Markup Language header
 */
void scan_html(scan_t *scan) {
	
	scan->length = scan->buf_len - scan->offset;
}

/*
 * Scan Hyper Text Transmission Protocol header
 */
void scan_http(scan_t *scan) {
	register char *http = (char *)(scan->buf + scan->offset);
	packet_state_t *packet = scan->packet;
	
	/*
	 * To calculate length we need to take it from ip header - tcp header
	 */
	char *buf = scan->buf;
	header_t tcph = packet->pkt_headers[packet->pkt_header_count -1];
	
	register int size = tcph.hdr_payload;
		
	scan->length = size;
		
#ifdef DEBUG
	char b[32];
	b[0] = '\0';
	b[31] = '\0';
	strncpy(b, http, (size <= 31)? size : 31);
		
	if (size < 10)
	printf("scan_http(): #%d INVALID size=%d http=%s\n", 
			(int) scan->packet->pkt_frame_num, size, b);
#endif 

		
	for (int i = 0; i < size; i ++){
		if (http[i] == '\r' && http[i + 1] == '\n' 
			&& http[i + 2] == '\r' && http[i + 3] == '\n') {
				
			scan->length = i + 4;
			break;
		}
	}
		
	return;
}

/**
 * Validate HTTP  header values at current scan.offset.
 * 
 * DO NOT CHANGE any scan properties. This is a completely passive method, only
 * the return value determines if validation passed or not. Return either
 * constant INVALID or header ID constant.
 */
int validate_http(scan_t *scan) {
	char *http = (char *)(scan->buf + scan->offset);
	packet_state_t *packet = scan->packet;
	
	/*
	 * To calculate length we need to take it from ip header - tcp header
	 */
	char *buf = scan->buf;
	header_t tcph = packet->pkt_headers[packet->pkt_header_count -1];
	
	int size = tcph.hdr_payload;
	
	/* First sanity check if we have printable chars */
	if (size < 5 || 
		(isprint(http[0]) && isprint(http[1]) && isprint(http[2])) == FALSE) {
		
#ifdef DEBUG
		char b[32];
		b[0] = '\0';
		b[31] = '\0';
		strncpy(b, http, (size <= 31)? size : 31);
		
		printf("scan_http(): UNMATCHED size=%d http=%s\n", size, b);
#endif 
		return INVALID;
	}
	
	if (	/* HTTP Response */
			strncmp(http, "HTTP", 4) == 0 ||
			
			/* HTTP Requests */
			strncmp(http, "GET", 3) == 0 || 
			strncmp(http, "OPTIONS", 7) == 0 || 
			strncmp(http, "HEAD", 4) == 0 || 
			strncmp(http, "POST", 4) == 0 || 
			strncmp(http, "PUT", 3) == 0 || 
			strncmp(http, "DELETE", 6) == 0 || 
			strncmp(http, "TRACE", 5) == 0 || 
			strncmp(http, "CONNECT", 7 == 0) ) {
		
#ifndef DEBUG
		char b[32];
		b[0] = '\0';
		b[31] = '\0';
		strncpy(b, http, (size <= 31)? size : 31);
		
		if (size < 10)
		printf("scan_http(): #%d INVALID size=%d http=%s\n", 
				(int) scan->packet->pkt_frame_num, size, b);
#endif 

	} 
	
	return HTTP_ID;
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
		scan->next_id = validate_next(IP4_ID, scan);
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
	case 0x0021: scan->next_id = validate_next(IP4_ID, scan); break;
	case 0x0057: scan->next_id = validate_next(IP6_ID, scan); break;
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
		scan->next_id = validate_next(PPP_ID, scan);
	}
}

/*
 * Scan IEEE 802.1q VLAN tagging header
 */
void scan_vlan(scan_t *scan) {
	vlan_t *vlan = (vlan_t *)(scan->buf + scan->offset);
	scan->length = sizeof(vlan_t);
	
	scan->next_id = validate_next(lookup_ethertype(vlan->type), scan);
	
	if (scan->next_id == PAYLOAD_ID) {
		scan->next_id = validate_next(IEEE_802DOT2_ID, scan);
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
	case 0xaa: scan->next_id = validate_next(IEEE_SNAP_ID, scan); break;
	}
}

/*
 * Scan IEEE SNAP header
 */
void scan_snap(scan_t *scan) {
	snap_t *snap = (snap_t *) (scan->buf + scan->offset);
	char *b = (char *) snap;
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
	
	switch (BIG_ENDIAN32(snap->oui)) {
	case 0x0000f8: // OUI_CISCO_90
	case 0: scan->next_id = 
		validate_next(lookup_ethertype(*(uint16_t *)(b + 3)), scan); break;
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
	
	switch (BIG_ENDIAN16(tcp->dport)) {
	case 80:
	case 8080:
	case 8081: scan->next_id = validate_next(HTTP_ID, scan);	return;
	case 5060: scan->next_id = validate_next(SIP_ID, scan);		return;		
	}
	
	switch (BIG_ENDIAN16(tcp->sport)) {
	case 80:
	case 8080:
	case 8081: scan->next_id = validate_next(HTTP_ID, scan);	return;
	case 5060: scan->next_id = validate_next(SIP_ID, scan);		return;
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
	case 1701: scan->next_id = validate_next(L2TP_ID, scan);	return;
	case 5060: scan->next_id = validate_next(SIP_ID, scan);		return;
	case 5004: scan->next_id = validate_next(RTP_ID, scan);		return;
	}
	
	switch (BIG_ENDIAN16(udp->sport)) {
	case 1701: scan->next_id = validate_next(L2TP_ID, scan);	return;
	case 5060: scan->next_id = validate_next(SIP_ID, scan);		return;
	case 5004: scan->next_id = validate_next(RTP_ID, scan);		return;
	}

}

/*
 * Scan Address Resolution Protocol header
 */
void scan_arp(scan_t *scan) {
	arp_t *arp = (arp_t *)(scan->buf + scan->offset);
	
	scan->length = (arp->hlen + arp->plen) * 2 + 8;
}

/*
 * Scan IP version 6
 */
void scan_ip6(scan_t *scan) {
	ip6_t *ip6 = (ip6_t *)(scan->buf + scan->offset);
	scan->length = IP6_HEADER_LENGTH;
	scan->hdr_payload = BIG_ENDIAN16(ip6->ip6_plen);
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
	int len;
	
//#define DEBUG
#ifdef DEBUG
	printf("#%d scan_ip6() type=%d (0x%x)\n", 
			(int)scan->packet->pkt_frame_num, 
			type, 
			type);
	fflush(stdout);
#endif
		
again:
	switch (type) {
	case 1: scan->next_id = validate_next(ICMP_ID, scan); break;
	case 4: scan->next_id = validate_next(IP4_ID, scan);  break;
	case 6: scan->next_id = validate_next(TCP_ID, scan);  break;
	case 17:scan->next_id = validate_next(UDP_ID, scan);  break;
	case 58:scan->next_id = validate_next(PAYLOAD_ID, scan); break; // ICMPv6 not implemented yet
	
	/* Ip6 Options - see RFC2460 */
	
	case 44:  // Fragment Header
		/* If we are a fragment, we just set the FRAG flag and pass through */
		scan->flags |= CUMULATIVE_FLAG_HEADER_FRAGMENTED;
		
	case 0:   // Hop-by-hop options (has special processing)
	case 60:  // Destination Options (with routing options)
	case 43:  // Routing header
	case 51:  // Authentication Header
	case 50:  // Encapsulation Security Payload Header
	case 135: // Mobility Header
		/* Skips over all option headers */
		type = (int) *(buf + 0); // Option type
		len = ((int) *(buf + 1)) * 8 + 8; // Option length
		if ((scan->offset + len) > scan->buf_len) { // Catch all just in case
			
#ifdef DEBUG
	printf("#%ld scan_ip6() infinite loop detected. Option type=%d len=%d offset=%d\n", 
			scan->packet->pkt_frame_num,
			type,
			len,
			scan->offset);
	fflush(stdout);
#endif
			scan->next_id = PAYLOAD_ID;
			break;
		}
		scan->length += len;
		scan->hdr_payload -= len; // Options are part of the main payload length
		buf += len;
		
#ifdef DEBUG
	printf("#%d scan_ip6() OPTION type=%d (0x%x) len=%d\n", 
			(int)scan->packet->pkt_frame_num, 
			type, 
			type,
			len);
	fflush(stdout);
#endif

		goto again;
	
	case 59:  // No next header
	default:
		if (scan->hdr_payload == 0) {
			scan->next_id = END_OF_HEADERS;
		} else {
			scan->next_id = PAYLOAD_ID;
		}
		break;
	}
}


/*
 * Scan IP version 4
 */
void scan_ip4(register scan_t *scan) {
	register ip4_t *ip4 = (ip4_t *) (scan->buf + scan->offset);
	scan->length = ip4->ihl * 4;
	scan->hdr_payload = BIG_ENDIAN16(ip4->tot_len) - scan->length;
	
	/* Check if this IP packet is a fragment and record in flags */
	int frag = BIG_ENDIAN16(ip4->frag_off);
	if (frag & IP4_FLAG_MF || (frag & IP4_FRAG_OFF_MASK > 0)) {
		scan->flags |= CUMULATIVE_FLAG_HEADER_FRAGMENTED;
	}
//#define DEBUG
#ifdef DEBUG
		printf("ip4->frag_off=%x\n", frag);
		fflush(stdout);
#endif
	
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
		case 1: scan->next_id = validate_next(ICMP_ID, scan); break;
		case 4: scan->next_id = validate_next(IP4_ID, scan);  break;
		case 6: scan->next_id = validate_next(TCP_ID, scan);  break;
		case 17:scan->next_id = validate_next(UDP_ID, scan);  break;
		case 115: scan->next_id = validate_next(L2TP_ID, scan); break;

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
		scan->next_id = validate_next(lookup_ethertype(eth->type), scan);
		
		return;
		
	} else {
		scan->next_id = validate_next(IEEE_802DOT2_ID, scan); // LLC v2
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
		scan->next_id = validate_next(IEEE_802DOT2_ID, scan); // LLC v2
		
	} else {
		scan->next_id = validate_next(lookup_ethertype(eth->type), scan);
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

/**
 * Validates the protocol with ID by advancing offset to next header. 
 * If a validation function is not found, INVALID is returned. Offset is 
 * restored to original value before this method retuns.
 */
int validate_next(register int id, register scan_t *scan) {
	
	register native_validate_func_t validate_func = validate_table[id];
	if (validate_func == NULL) {
		return id; 
	}

	int saved_offset = scan->offset;
	scan->offset += scan->length + scan->hdr_gap;
	
	int result = validate_func(scan);
	
	scan->offset = saved_offset;
	
	return result;
}

/**
 * Validates the protocol with ID. If a validation function is not found,
 * INVALID is returned.
 */
int validate(register int id, register scan_t *scan) {
	
	register native_validate_func_t validate_func = validate_table[id];
	if (validate_func == NULL) {
		return id; 
	}
		
	return validate_func(scan);
}


int lookup_ethertype(uint16_t type) {
//	printf("type=0x%x\n", BIG_ENDIAN16(type));
	switch (BIG_ENDIAN16(type)) {
	case 0x0800: return IP4_ID;
	case 0x0806: return ARP_ID;
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
	
	/*
	 * Initialize the inmemory table
	 */
	memset(native_protocols, 0, MAX_ID_COUNT * sizeof(native_protocol_func_t));
	memset(native_heuristics, 0, 
			MAX_ID_COUNT * MAX_ID_COUNT * sizeof(native_validate_func_t));
	
	// Builtin families
	native_protocols[PAYLOAD_ID]  = &scan_payload;
	
	// Datalink families
	native_protocols[ETHERNET_ID]      		= &scan_ethernet;
	native_protocols[IEEE_802DOT2_ID]  		= &scan_llc;
	native_protocols[IEEE_SNAP_ID]     		= &scan_snap;
	native_protocols[IEEE_802DOT1Q_ID] 		= &scan_vlan;
	native_protocols[L2TP_ID]          		= &scan_l2tp;
	native_protocols[PPP_ID]           		= &scan_ppp;
	native_protocols[IEEE_802DOT3_ID]		= &scan_802dot3;
	native_protocols[SLL_ID]				= &scan_sll;
	
	// TCP/IP families
	native_protocols[IP4_ID]      			= &scan_ip4;
	native_protocols[IP6_ID]      			= &scan_ip6;
	native_protocols[UDP_ID]      			= &scan_udp;
	native_protocols[TCP_ID]      			= &scan_tcp;
	native_protocols[ICMP_ID]     			= &scan_icmp;
	native_protocols[HTTP_ID]     			= &scan_http;
	native_protocols[HTML_ID]     			= &scan_html;
	native_protocols[ARP_ID]      			= &scan_arp;
	
	// Voice and Video
	native_protocols[SIP_ID]     			= &scan_sip;
	native_protocols[SDP_ID]     			= &scan_sdp;
	native_protocols[RTP_ID]     			= &scan_rtp;
	
	
	/*
	 * Validation function table. This isn't the list of bindings, but 1 per
	 * protocol. Used by validate(scan) function.
	 */ 
	validate_table[HTTP_ID] 				= &validate_http;
	validate_table[SIP_ID]					= &validate_sip;
	validate_table[RTP_ID]					= &validate_rtp;
	
	
	/*
	 * Heuristic bindings (guesses) to protocols. Used by main scan loop to
	 * check heuristic bindings.
	 */
	native_heuristics[TCP_ID][0]			= &validate_http;
	native_heuristics[TCP_ID][1]			= &validate_sip;

	native_heuristics[UDP_ID][0]			= &validate_rtp;
	
	/*
	 * Now store the names of each header, used for debuggin purposes
	 */
	native_protocol_names[PAYLOAD_ID]       = "PAYLOAD";
	native_protocol_names[ETHERNET_ID]      = "ETHERNET";
	native_protocol_names[TCP_ID]           = "TCP";
	native_protocol_names[UDP_ID]           = "UDP";
	native_protocol_names[IEEE_802DOT3_ID]  = "802DOT3";
	native_protocol_names[IEEE_802DOT2_ID]  = "802DOT2";
	native_protocol_names[IEEE_SNAP_ID]     = "SNAP";
	native_protocol_names[IP4_ID]           = "IP4";
	native_protocol_names[IP6_ID]           = "IP6";
	native_protocol_names[IEEE_802DOT1Q_ID] = "802DOT1Q";
	native_protocol_names[L2TP_ID]          = "L2TP";
	native_protocol_names[PPP_ID]           = "PPP";
	native_protocol_names[ICMP_ID]          = "ICMP";
	native_protocol_names[HTTP_ID]          = "HTTP";
	native_protocol_names[HTML_ID]          = "HTML";
	native_protocol_names[ARP_ID]           = "ARP";
	native_protocol_names[SIP_ID]           = "SIP";
	native_protocol_names[SDP_ID]           = "SDP";
	native_protocol_names[RTP_ID]           = "RTP";
	native_protocol_names[SLL_ID]           = "SLL";
}

