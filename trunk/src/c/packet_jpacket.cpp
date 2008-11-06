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

#include "nio_jmemory.h"
#include "packet_jscanner.h"
#include "jnetpcap_utils.h"
#include "org_jnetpcap_packet_JPacket_State.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions. Private scan function
 * 
 * **************************************************************
 ****************************************************************/
/*
 * finds a specific header instance
 */
jint findHeaderById(packet_state_t *packet, jint id, jint instance) {
//	printf("findHeaderIndex(%d, %d)\n", id, instance);
//	fflush(stdout);
	
	if (packet->pkt_instance_counts[id] < instance) {
		return -1;
	}
	
	for (int i = 0; i < packet->pkt_header_count; i ++ ) {
		header_t *header = &packet->pkt_headers[i];
		
		if (header->hdr_id == id) {
			
			if (instance == 0) {
				return i;
			} else {
				instance --;
			}
		}
	}

	return -1;
}

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_sizeof
  (JNIEnv *env, jclass clazz) {
	
	return (jint) sizeof(packet_state_t);
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    findHeaderIndex
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_findHeaderIndex
  (JNIEnv *env, jobject obj, jint id, jint instance) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	return (jint) findHeaderById(packet, id, instance);
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    get64BitHeaderMap
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_packet_JPacket_00024State_get64BitHeaderMap
  (JNIEnv *env, jobject obj, jint index) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}

	return (jlong) packet->pkt_header_map;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getHeaderCount
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getHeaderCount
  (JNIEnv *env, jobject obj) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}

	return (jint) packet->pkt_header_count;

}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getInstanceCount
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getInstanceCount
  (JNIEnv *env, jobject obj, jint id) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}

	return (jint) packet->pkt_instance_counts[id];
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getHeaderIdByIndex
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getHeaderIdByIndex
  (JNIEnv *env, jobject obj, jint index) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}

	return (jint) packet->pkt_headers[index].hdr_id;

}


/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    peerHeaderById
 * Signature: (IILorg/jnetpcap/packet/JHeader$State;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_peerHeaderById
  (JNIEnv *env, jobject obj, jint id, jint instance, jobject dst) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	int index = findHeaderById(packet, id, instance);
	if (index == -1) {
		return -1;
	}
	
	setJMemoryPhysical(env, dst, toLong(&packet->pkt_headers[index]));

	return sizeof(header_t);
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    peerHeaderByIndex
 * Signature: (ILorg/jnetpcap/packet/JHeader$State;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_peerHeaderByIndex
  (JNIEnv *env, jobject obj, jint index, jobject dst) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	if (index >= packet->pkt_header_count) {
		return -1;
	}
	
	setJMemoryPhysical(env, dst, toLong(&packet->pkt_headers[index]));

	return sizeof(header_t);
}
