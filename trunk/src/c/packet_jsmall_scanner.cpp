/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */

#include <stdio.h>
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

/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions. Private scan function
 * 
 * **************************************************************
 ****************************************************************/

/**
 * Prepares a scan of packet buffer
 */
int scanJPacket(JNIEnv *env, jobject obj, jobject jpacket, jobject jstate,
		scanner_t *scanner, int first_id, char *buf, int buf_length) {

	/* Check if we need to wrap our entry buffer around */
	if (scanner->sc_offset > scanner->sc_len - sizeof(header_t)
			* MAX_ENTRY_COUNT) {
		scanner->sc_offset = 0;
	}

	packet_state_t *packet =(packet_state_t *)(((char *)scanner->sc_packet)
			+ scanner->sc_offset);

	/*
	 * Peer JPacket.state to packet_state_t structure
	 */
	setJMemoryPhysical(env, jstate, toLong(packet));

	/* 
	 * Initialize the packet_state_t structure for new packet entry. We need to 
	 * initialize everything since we may be wrapping around and writting over 
	 * previously stored data.
	 */
	packet->pkt_header_map = 0;
	packet->pkt_data = buf;
	packet->pkt_header_count = 0;

	scanner->sc_offset +=scan(env, obj, jpacket, scanner, packet, first_id,
			buf, buf_length);
}

/**
 * Scan packet buffer
 */
int scan(JNIEnv *env, jobject obj, jobject jpacket, scanner_t *scanner,
		packet_state_t *packet, int first_id, char *buf, int buf_len) {

	ethernet_t *eth;
	ip4_t *ip4;
	tcp_t *tcp;
	udp_t *udp;
	llc_t *llc;
	snap_t *snap;
	vlan_t *vlan;
	l2tp_t *l2tp;
	ppp_t *ppp;
	icmp_t *icmp;

	header_t *header = packet->pkt_headers;

	register uint64_t binding_map = scanner->sc_binding_map;
	uint64_t *override_map = scanner->sc_override_map;
	uint64_t *dependency_map = scanner->sc_dependency_map;
	register int32_t count = 0; /* number of header_t entries */
	register uint32_t offset = 0; /* offset into packet data buffer */
	register int32_t id = first_id;
	register uint64_t mask;
	register uint32_t length = 0; /* length of the protocol header */
	register int32_t next_id = PAYLOAD_ID;
//#define DEBUG
	/*
	 * Main scanner loop, 1st scans for builtin header types then
	 * reverts to calling on JBinding objects to provide the binding chain
	 */
	while (id != -1) {

#ifdef DEBUG
		printf("scan() loop-top: id=%s offset=%d\n", id2str(id), offset);
		fflush(stdout);
#endif
		/*
		 * Now check the builtin/hardcoded bindings
		 */
		switch (id) {
		
		case ICMP_ID:
			icmp = (icmp_t *)(buf + offset);
			length = sizeof(icmp_t);
			break;

		
		case PPP_ID:
			ppp = (ppp_t *)(buf + offset);
			length = sizeof(ppp_t);
			
			switch (BIG_ENDIAN16(ppp->protocol)) {
			case 0x0021:
				next_id = IP4_ID;
				break;
			}
			break;

			
		case L2TP_ID:
			l2tp = (l2tp_t *)(buf + offset);
			length = 6;
			if (l2tp->l == 1) {
				length += 2;
			}
			if (l2tp->s == 1) {
				length += 4;
			}
			if (l2tp->o == 1) {
				length += 4;
			}

#ifdef DEBUG
			printf("scan() lL2TP_ID: b[0]=%d t=%d\n", 
					(int)*(buf + offset), l2tp->t);
			fflush(stdout);
#endif
			
			if (l2tp->t == 0) {
				next_id = PPP_ID;
			}
			break;
			
		case IEEE_802DOT1Q_ID:
			vlan = (vlan_t *)(buf + offset);
			
			ETHERTYPE_SWITCH(vlan->type);
			break;


		case IEEE_802DOT2_ID:
			llc = (llc_t *) (buf + offset);
			if (llc->control & 0x3 == 0x3) {
				length = 3;
			} else {
				length = 4;
			}

			switch (llc->dsap) {
			case 0xaa:
				next_id = org_jnetpcap_packet_JProtocol_IEEE_SNAP_ID;
				break;

			}
			break;

		case IEEE_SNAP_ID:
			snap = (snap_t *) (buf + offset);
			length = sizeof(snap_t);

			switch (snap->oui) {
			case 0: // Ethernet types
				ETHERTYPE_SWITCH(snap->pid); // defined inpacket_protocol.h
				break;

			}

		case IEEE_802DOT3_ID:
		case ETHERNET_ID:
			eth = (ethernet_t *) (buf + offset);
			length = sizeof(ethernet_t);
		
			if (BIG_ENDIAN16(eth->type) < 0x600) { // We have an IEEE 802.3 frame
				id      = IEEE_802DOT3_ID;
				next_id = IEEE_802DOT2_ID; // LLC v2
				break;
			}
		
			ETHERTYPE_SWITCH(eth->type);  // defined in packet_protocol.h
	
			break;
		
	
		case IP4_ID:
			ip4 = (ip4_t *) (buf + offset);
			length = ip4->ihl * 4;

#ifdef DEBUG
			printf("scan() IP4_ID: type=%d frag_off=%d @ frag_off.pos=%X\n", 
					ip4->protocol, 
					BIG_ENDIAN16(ip4->frag_off) & IP4_FRAG_OFF_MASK, 
					(int)((char *)&ip4->frag_off - buf));
			fflush(stdout);
#endif

			if ( (BIG_ENDIAN16(ip4->frag_off) & IP4_FRAG_OFF_MASK) != 0) {
				next_id = PAYLOAD_ID;
				break;
			}
		
			switch (ip4->protocol) {
				case 1: // ICMP
				next_id = ICMP_ID;
				break;

				case 4: // IP in IP
				next_id = IP4_ID;
				break;
		
				case 6: // TCP
				next_id = TCP_ID;
				break;
		
				case 17: // UDP
				next_id = UDP_ID;
				break;
		
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
				//			case 115: // L2TP
				//			case 132: // SCTP, Stream Control Transmission Protocol
				//			case 137: // MPLS in IP
		
		
			}	
			break;
	
		case TCP_ID:
			tcp = (tcp_t *) (buf + offset);
			length = sizeof(tcp_t);
			break;
	
		case UDP_ID:
			udp = (udp_t *) (buf + offset);
			length = sizeof(udp_t);	
			
			switch (BIG_ENDIAN16(udp->dport)) {
			case 1701:
				next_id = L2TP_ID;
				break;
			}
			break;
			
		case PAYLOAD_ID:
//		default:
			id = PAYLOAD_ID;
			next_id = -1;
			length = buf_len - offset;
			break;
		}

#ifdef DEBUG
		printf("scan() loop-bottom: id=%s nid=%s length=%d offset=%d\n", 
				id2str(id), id2str(next_id), length, offset);
		fflush(stdout);
#endif
		
		/******************************************************
		 * ****************************************************
		 * Now record discovered information in structures
		 * ****************************************************
		 ******************************************************/
		
		mask = 1 << id;
		
		/*
		 * Initialize the header entry in our packet header array
		 */
		header->hdr_id = id;
		header->hdr_offset = offset;
		
		/*
		 * Initialize the instance count array entry if header is being set
		 * for the first time. Otherwise just increment. We are overriding
		 * area of memory that has previously been written into. Therefore there
		 * is bound to be an invalid value already in the array entry slot. 
		 */
		if ((packet->pkt_header_map & mask) == 0) {
			packet->pkt_instance_counts[id] = 1;
		} else {
			packet->pkt_instance_counts[id] ++;
		
		}
		
		packet->pkt_header_map |= mask;
		
		/*
		 * Adjust for truncated packets
		 */
		length = ((length > buf_len - offset)?buf_len - offset:length);
		
		/*
		 * Now process JBindings under the following conditions. Read inline...
		 */
		if (
				/* 
				 * Check if current header has any JBindings registered at all 
				 */
				(binding_map & mask) != 0&&
		
				/* 
				 * check if anything matched or if we have core header override. Core
				 * headers have a builtin/hardcoded scan algorithms just look above
				 * in the switch statements. override_map[id] per header ID allows
				 * overriding of builtin bindings with user supplied JBinding. If the
				 * resolved next_id through the core routine is overriden for current
				 * header  and of course, there were some JBindings for current header,
				 * then we process the binding, overriding what the builtin algorithm
				 * produced. 
				 *    
				 * condition group: (() || ()) 
				 */
				((next_id == PAYLOAD_ID) != 0 /* Check if we failed to match */
		
						/* or we have an override core with JBinding? */
						|| (override_map[id]& (1 << next_id))
		
				)&&
				/* 
				 * Lastly sanity check if we have the required headers already found
				 * in the packet to even attempt the JBindings. No point in processing
				 * any JBindings if the necessary header dependencies/prerequisites 
				 * haven't been found by now in the packet. dependancy_map is 
				 * cumulative mask of IDs for all required headers. Each dependancy 
				 * within the array to be scanned has its own individual dependancy 
				 * map as well.
				 */
				(binding_map & dependency_map[next_id]) != 0) {
		
			packet->pkt_header_count = count;
		
			next_id= scanJavaBinding(env, obj, jpacket, scanner, packet,
					offset, id, buf, buf_len, header);
			length = header->hdr_length;
		
		} else {
			header->hdr_length = length;
		}
		
		offset += length;
		
		header ++; /* point to next header entry *** ptr arithmatic */
		count ++; /* number of entries */
		
		id = next_id;
		next_id = PAYLOAD_ID;
		length = 0;
	}
	
	/* record number of header entries found */
	packet->pkt_header_count = count;
	
#ifdef DEBUG
		printf("scan(): header_count=%d offset=%d header_map=%x\n", 
				count, 
				offset, 
				packet->pkt_header_map);
#endif
		
	return offset;
}

char *id2str(int id) {
	switch (id) {
	case ETHERNET_ID      :return "ETHERNET";
	case TCP_ID           :return "TCP";
	case UDP_ID           :return "UDP";
	case IEEE_802DOT3_ID  :return "IEEE_802DOT3";
	case IEEE_802DOT2_ID  :return "IEEE_802DOT2";
	case IEEE_SNAP_ID     :return "IEEE_SNAP";
	case IP4_ID           :return "IP4";
	case IP6_ID           :return "IP6";
	case IEEE_802DOT1Q_ID :return "IEEE_802DOT1Q";
	case L2TP_ID	 	  :return "L2TP";
	case PPP_ID      	  :return "PPP";
	case ICMP_ID 		  :return "ICMP";
	default               :return "NO_NAME";
	}
}

/**
 * Scan packet buffer by dispatching to JBinding java objects
 */
int scanJavaBinding(JNIEnv *env, jobject obj, jobject jpacket,
		scanner_t *scanner, packet_state_t *packet, int offset, int id,
		char *buf, int buf_len, header_t *header) {

	binding_t *binding = scanner->sc_bindings[id];

	while (binding->bnd_id != -1) {
		/*
		 * Check if we have required dependencies already found in the packet
		 */
		if ( (packet->pkt_header_map & binding->bnd_dependency_map) != 0) {
			/*
			 * Call on JBinding to see if it passes 
			 */
			int length = env->CallIntMethod(binding->bnd_jbinding,
					jbindingCheckLengthMID, jpacket, (jint) offset);
			if (length != 0) {
				/*
				 * Adjust for truncated packets
				 */
				length = ((length > buf_len - offset) ? buf_len - offset
						: length);

				header->hdr_length = length;
				return binding->bnd_id;
			}
		}

		binding ++; /* ptr arithmatic */
	}
}

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

jclass jdependencyClass = NULL;
jclass jbindingClass = NULL;

jmethodID getIdMID = 0;
jmethodID listDependenciesMID = 0;
jmethodID jbindingCheckLengthMID = 0;

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    initIds
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_initIds
(JNIEnv *env, jclass clazz) {

	if ( (jdependencyClass = findClass(
							env, "org/jnetpcap/packet/JDependency")) == NULL) {
		return;
	}

	if ( (jbindingClass = findClass(
							env, "org/jnetpcap/packet/JBinding")) == NULL) {
		return;
	}

	if ( (listDependenciesMID = env->GetMethodID(
							jdependencyClass, "listDependencies", "()[I")) == NULL) {
		return;
	}

	if ( (getIdMID = env->GetMethodID(
							jdependencyClass, "getId", "()I")) == NULL) {
		return;
	}

	if ( (jbindingCheckLengthMID = env->GetMethodID(
							jbindingClass,
							"checkLength",
							"(Lorg/jnetpcap/packet/JPacket;I)I")) == NULL) {
		return;
	}

}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScanner_sizeof
(JNIEnv *env, jclass obj) {
	return (jint)sizeof(scanner_t);
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    init
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_init
(JNIEnv *env, jobject obj) {
	void *block = (char *)getJMemoryPhysical(env, obj);
	size_t size = (size_t)env->GetIntField(obj, jmemorySizeFID);

	memset(block, 0, size);

	scanner_t *scanner = (scanner_t *)block;
	scanner->sc_len = size - sizeof(scanner_t);
	scanner->sc_offset = 0;
	scanner->sc_packet = (packet_state_t *)((char *)block + sizeof(scanner_t));
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    loadBindings
 * Signature: (I[Lorg/jnetpcap/packet/JBinding;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_loadBindings
(JNIEnv *env, jobject obj, jint jid, jobjectArray jbindings) {
	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

	jsize size = env->GetArrayLength(jbindings);
	printf("loadBindings(): loaded %d bindigns\n", (int)size);

	binding_t *bindings = scanner->sc_bindings[(int) jid];

	for (int i = 0; i < size; i ++) {
		jobject jbinding = env->GetObjectArrayElement(jbindings, (jsize) i);

		if (jbinding != NULL) {

			int id = (int) env->CallIntMethod(jbinding, getIdMID);
			bindings[i].bnd_id = id;
			bindings[i].bnd_jbinding = jbinding;

			scanner->sc_binding_map |= ((uint64_t)1) << id;

			jintArray jdependencies = (jintArray)
			env->CallObjectMethod(jbinding, listDependenciesMID);

			bindings[i].bnd_dependency_map = toUlong64(env, jdependencies);

			env->DeleteLocalRef(jdependencies);
		}

		env->DeleteLocalRef(jbinding);
	}
}

/**
 * Converts a java array of ints to a unsinged 64 bit long bit map
 */
uint64_t toUlong64(JNIEnv *env, jintArray ja) {
	uint64_t r = 0;

	jint * intarray = env->GetIntArrayElements(ja, NULL);
	jsize length = env->GetArrayLength(ja);

	for (jsize i = 0; i < length; i ++) {
		r |= ((uint64_t)1) << intarray[i];
	}

	env->ReleaseIntArrayElements(ja, intarray, JNI_ABORT);

	return r;
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    loadDependencies
 * Signature: (I[I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_loadDependencies
(JNIEnv *env, jobject obj, jint, jintArray jdependencies) {
	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    loadOverride
 * Signature: ([I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_loadOverride
(JNIEnv *env, jobject obj, jintArray joverrides) {
	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    resetBindings
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_resetBindings
(JNIEnv *env, jobject obj) {
	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

	scanner->sc_binding_map = 0L;
	memset((void *)scanner->sc_bindings, 0,
			sizeof(binding_t) * MAX_ID_COUNT * MAX_BINDING_COUNT);

}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    resetDependencies
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_resetDependencies
(JNIEnv *env, jobject obj) {
	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

	memset((void *)scanner->sc_dependency_map, 0,
			sizeof(uint64_t) * MAX_ID_COUNT);
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    resetOverride
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_resetOverride
(JNIEnv *env, jobject obj) {
	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

	memset((void *)scanner->sc_override_map, 0,
			sizeof(uint64_t) * MAX_ID_COUNT);
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    scan
 * Signature: (Lorg/jnetpcap/packet/JPacket;Lorg/jnetpcap/packet/JPacket$State;I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScanner_scan
(JNIEnv *env, jobject obj, jobject jpacket, jobject jstate, jint id) {

	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return -1;
	}

	char *buf = (char *)getJMemoryPhysical(env, jpacket);
	if (scanner == NULL) {
		return -1;
	}

	int size = (int)env->GetIntField(jpacket, jmemorySizeFID);

	return scanJPacket(env, obj, jpacket, jstate, scanner, id, buf, size);
}

