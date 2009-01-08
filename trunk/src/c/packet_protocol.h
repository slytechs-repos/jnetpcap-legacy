/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_packet_protocol_h
#define _Included_jnetpcap_packet_protocol_h
#ifdef __cplusplus

#include <stdint.h>

#include "export.h"
#include <jni.h>
#include "nio_jbuffer.h"
#include "org_jnetpcap_packet_JProtocol.h"
#include "org_jnetpcap_packet_JScan.h"

// Proto types
char *id2str(int id);

#define END_OF_HEADERS   org_jnetpcap_packet_JScan_END_OF_HEADERS_ID
#define ETHERNET_ID      org_jnetpcap_packet_JProtocol_ETHERNET_ID
#define TCP_ID           org_jnetpcap_packet_JProtocol_TCP_ID
#define UDP_ID           org_jnetpcap_packet_JProtocol_UDP_ID
#define IEEE_802DOT3_ID  org_jnetpcap_packet_JProtocol_IEEE_802DOT3_ID
#define IEEE_802DOT2_ID  org_jnetpcap_packet_JProtocol_IEEE_802DOT2_ID
#define IEEE_SNAP_ID     org_jnetpcap_packet_JProtocol_IEEE_SNAP_ID
#define IP4_ID           org_jnetpcap_packet_JProtocol_IP4_ID
#define IP6_ID           org_jnetpcap_packet_JProtocol_IP6_ID
#define IEEE_802DOT1Q_ID org_jnetpcap_packet_JProtocol_IEEE_802DOT1Q_ID
#define L2TP_ID          org_jnetpcap_packet_JProtocol_L2TP_ID
#define PPP_ID           org_jnetpcap_packet_JProtocol_PPP_ID
#define ICMP_ID          org_jnetpcap_packet_JProtocol_ICMP_ID


typedef struct icmp_t {
	uint8_t type;
	uint8_t code;
	uint16_t crc;

} icmp_t;

typedef struct ppp_t {
	uint8_t addr;
	uint8_t control;
	uint16_t protocol;
};

typedef struct l2tp_t {
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t p :1;
	uint16_t o :1;
	uint16_t res2 :1;
	uint16_t s :1;
	uint16_t res1 :2;
	uint16_t l :1;
	uint16_t t :1;
	uint16_t version :4;
	uint16_t res3 :4;
#  elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t t:1;
	uint16_t l:1;
	uint16_t res1:2;
	uint16_t s:1;
	uint16_t res2:1;
	uint16_t o:1;
	uint16_t p:1;
	uint16_t res3:4;
	uint16_t version:4;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif

} l2tp_t;

typedef struct vlan_t {
	uint16_t priority :3;
	uint16_t cfi :1;
	uint16_t id :12;

	uint16_t type;
} vlan_t;

/**
 * SNAP IEEE
 */
typedef union snap_t {
	uint32_t oui :24;
	struct {
		uint8_t reserved[3];
		uint16_t pid;
	};
} snap_t;

/**
 * LLC IEEE802.2
 */
typedef struct llc_t {
	uint8_t dsap;
	uint8_t ssap;
	uint8_t control;
	union {
		uint8_t info;
	} ucontrol;
} llc_t;

/**
 * UDP structure
 */
typedef struct udp_t {
	uint16_t sport;
	uint16_t dport;
	uint16_t length;
	uint16_t checksum;

} udp_t;

/**
 * TCP structure
 */
typedef struct tcp_t {
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t res1 :4;
	uint16_t doff :4;
	uint16_t fin :1;
	uint16_t syn :1;
	uint16_t rst :1;
	uint16_t psh :1;
	uint16_t ack :1;
	uint16_t urg :1;
	uint16_t res2 :2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
} tcp_t;

/**
 * Ethernet 2 structure
 */
typedef struct ethernet_t {
	uint8_t dhost[6]; /* destination eth addr */
	uint8_t shost[6]; /* destination eth addr */
	uint16_t type; /* destination eth addr */
} ethernet_t;

/**
 * IP v6 structure
 * RFC 1883
 */
typedef struct ip6 {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			uint16_t ip6_un1_plen;	/* payload length */
			uint8_t  ip6_un1_nxt;	/* next header */
			uint8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;	/* 4 bits version, 4 bits class */
	} ip6_ctlun;
	uint8_t ip6_src[16];	/* source address */
	uint8_t ip6_dst[16];	/* destination address */
} ip6_t;

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim


/**
 * IP v4 structure
 */
typedef struct ip4 {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl :4;
	unsigned int version :4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off; // flags=3 bits, offset=13 bits
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
	/*The options start here. */
} ip4_t;

#define IP4_FLAGS_MASK 0xE000
#define IP4_FRAG_OFF_MASK ~IP4_FLAGS_MASK


/****************************************************************
 * **************************************************************
 * 
 * Scanner's native and java per protocol prototypes
 * 
 * **************************************************************
 ****************************************************************/

int lookup_ethertype(uint16_t type);
//
//void scan_ethernet (scan_t *scan);
//void scan_ip4      (scan_t *scan);


#endif
#endif
