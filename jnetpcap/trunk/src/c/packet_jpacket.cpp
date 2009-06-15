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
	
//	if (packet->pkt_instance_counts[id] < instance) {
//		return -1;
//	}
	
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
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_sizeof__I
(JNIEnv *env, jclass clazz, jint count) {
	
	return (jint) sizeof(packet_state_t) + sizeof(header_t) * count;
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
 * Method:    getAnalysis
 * Signature: ()Lorg/jnetpcap/analysis/JAnalysis;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getAnalysis

  (JNIEnv *env, jobject obj) {
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return NULL;
	}

	return packet->pkt_analysis;
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
	
	int count = 0;
	for (int i = 0; i < packet->pkt_header_count; i ++) {
		if (packet->pkt_headers[i].hdr_id == id) {
			count ++;
		}
	}

	return (jint) count;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getFlags
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getFlags
  (JNIEnv *env, jobject obj) {

	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	return (jint) packet->pkt_flags;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    setFlags
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JPacket_00024State_setFlags
  (JNIEnv *env, jobject obj, jint jflags) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return;
	}
	
	packet->pkt_flags = (uint8_t) jflags;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getWirelen
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getWirelen
  (JNIEnv *env, jobject obj) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	return (jint) packet->pkt_wirelen;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    setWirelen
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JPacket_00024State_setWirelen
  (JNIEnv *env, jobject obj, jint jwirelen) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return;
	}
	
	packet->pkt_wirelen = (uint32_t) jwirelen;
}



/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getFrameNumber
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getFrameNumber
  (JNIEnv *env, jobject obj) {
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}

	return (jint) packet->pkt_frame_num;
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
	
	if (index < 0 || index >= packet->pkt_header_count) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "header index out of range");
		return -1;
	}

	
//	printf("state=%p, index=%d, value=%d, delta=%d\n", 
//			packet,
//			(int) index,
//			(int) packet->pkt_headers[index].hdr_id,
//			(int) ((char *)&packet->pkt_headers[index].hdr_id - (char *)packet));
//	fflush(stdout);

	return (jint) packet->pkt_headers[index].hdr_id;

}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getHeaderLengthByIndex
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getHeaderLengthByIndex
  (JNIEnv *env, jobject obj, jint index) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	if (index < 0 || index >= packet->pkt_header_count) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "header index out of range");
		return -1;
	}

	return (jint) packet->pkt_headers[index].hdr_length;
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    getHeaderOffsetByIndex
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JPacket_00024State_getHeaderOffsetByIndex
  (JNIEnv *env, jobject obj, jint index) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return -1;
	}
	
	if (index < 0 || index >= packet->pkt_header_count) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "header index out of range");
		return -1;
	}

	return (jint) packet->pkt_headers[index].hdr_offset;
}


/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    setAnalysis
 * Signature: (Lorg/jnetpcap/packet/analysis/JAnalysis;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JPacket_00024State_setAnalysis__Lorg_jnetpcap_packet_analysis_JAnalysis_2
  (JNIEnv *env, jobject obj, jobject analysis) {
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		throwVoidException(env, NULL_PTR_EXCEPTION);
		return;
	}
	
	if (packet->pkt_analysis != NULL) {
		/* params: packet_state_t struct and analysis JNI global reference */
		jmemoryRefRelease(env, obj, packet->pkt_analysis);
	}

	if (analysis == NULL) {
		packet->pkt_analysis = NULL;
	} else	{
		/* params: packet_state_t struct and analysis JNI local reference */
		packet->pkt_analysis = jmemoryRefCreate(env, obj, analysis);
	}
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    setAnalysis
 * Signature: (ILorg/jnetpcap/packet/analysis/JAnalysis;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JPacket_00024State_setAnalysis__ILorg_jnetpcap_packet_analysis_JAnalysis_2
  (JNIEnv *env, jobject obj, jint id, jobject analysis) {
		
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		throwVoidException(env, NULL_PTR_EXCEPTION);
		return;
	}
	
	if (id < 0 || id >= packet->pkt_header_count) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "header index out of range");
		return;
	}
	
	header_t *header = &packet->pkt_headers[id];
	
	if (header == NULL) {
		throwVoidException(env, NULL_PTR_EXCEPTION);
		return;
	}

	if (header->hdr_analysis != NULL) {
		/* params: packet_state_t struct and analysis JNI global reference */
		jmemoryRefRelease(env, obj, header->hdr_analysis);
	}

	if (analysis == NULL) {
		header->hdr_analysis = NULL;
	} else	{
		/* params: packet_state_t struct and analysis JNI local reference */
		header->hdr_analysis = jmemoryRefCreate(env, obj, analysis);
	}
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
	jobject keeper = env->GetObjectField(obj, jmemoryKeeperFID);
	env->SetObjectField(dst, jmemoryKeeperFID, keeper);

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

/*
 * Class:     org_jnetpcap_packet_JHeader
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JHeader_sizeof
  (JNIEnv *env, jclass clazz) {
	
	return (jint) sizeof(header_t);
}

/*
 * Class:     org_jnetpcap_packet_JPacket_State
 * Method:    toDebugStringJPacketState
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_jnetpcap_packet_JPacket_00024State_toDebugStringJPacketState
  (JNIEnv *env, jobject obj) {
	
	char buf[15 * 1024];
	buf[0] = '\0';
	
	packet_state_t *packet = (packet_state_t *)getJMemoryPhysical(env, obj);
	if (packet == NULL) {
		return NULL;
	}
	
	int fr = packet->pkt_frame_num;
	
	sprintf(buf, 
			"JPacket.State#%03d: sizeof(packet_state_t)=%d\n"
			"JPacket.State#%03d: sizeof(header_t)=%d and *%d=%d\n"
			"JPacket.State#%03d:   pkt_header_map=0x%X\n"
			"JPacket.State#%03d:        pkt_flags=0x%x\n"
			"JPacket.State#%03d: pkt_header_count=%d\n"
			"JPacket.State#%03d:      pkt_wirelen=%d\n",
			fr, sizeof(packet_state_t),
			fr, sizeof(header_t), 
				packet->pkt_header_count,	
				sizeof(header_t) * packet->pkt_header_count,
			fr, (int) packet->pkt_header_map,
			fr, packet->pkt_flags,
			fr, packet->pkt_header_count,
			fr, packet->pkt_wirelen);
	
	char *p;
	
	for (int i = 0; i < packet->pkt_header_count; i ++) {
		p = buf + strlen(buf);
		sprintf(p, 
				"JPacket.State#%03d[%d]: "
				"[id=%-2d %-10s "
				"flags=0x%x "
				"pre=%d "
				"hdr_offset=%-4d "
				"hdr_length=%-3d "
				"gap=%d "
				"pay=%-3d "
				"post=%d]\n", 
				fr,	i,
				packet->pkt_headers[i].hdr_id,
				id2str(packet->pkt_headers[i].hdr_id),
				packet->pkt_headers[i].hdr_flags,
				packet->pkt_headers[i].hdr_prefix,
				packet->pkt_headers[i].hdr_offset,
				packet->pkt_headers[i].hdr_length,
				packet->pkt_headers[i].hdr_gap,
				packet->pkt_headers[i].hdr_payload,
				packet->pkt_headers[i].hdr_postfix
				);
		
	}
	
	return env->NewStringUTF(buf);
}

