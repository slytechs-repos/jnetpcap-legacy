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

#include "packet_flow.h"
#include "nio_jmemory.h"
#include "packet_jscanner.h"
#include "jnetpcap_utils.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions. Private scan function
 * 
 * **************************************************************
 ****************************************************************/
/**
 * Post processes the flow key data. If hashcode is not computed it computes one.
 * Fills in the flow_t.reverse_pairs array if FLOW_KEY_FLAG_REVERSABLE_PAIRS is set.
 * It also computes a different kind of hashcode if that flag is set. The hash
 * is direction independent. Otherwise the hashcode will be direction dependent.
 */
void process_flow_key(scan_t *scan) {
	flow_key_t *key = &scan->packet->pkt_flow_key;

	if (key->flags & FLOW_KEY_FLAG_REVERSABLE_PAIRS) {
		for (int i = 0; i < key->pair_count; i ++) {
			key->reverse_pair[i][0] = key->forward_pair[i][1];
			key->reverse_pair[i][1] = key->forward_pair[i][0];
		}
	}

	if (key->hash == 0) {

		key->hash = ((uint32_t) key->header_map) ^ (key->header_map >> 32)
				^ key->flags;

		if (key->flags & FLOW_KEY_FLAG_REVERSABLE_PAIRS) {
			for (int i = 0; i < key->pair_count; i ++) {
				key->hash ^= key->reverse_pair[i][0];
				key->hash ^= key->reverse_pair[i][1];
			}
		} else {
			for (int i = 0; i < key->pair_count; i ++) {
				key->hash ^= key->forward_pair[i][0] << 16;
				key->hash ^= key->forward_pair[i][0] >> 16;
				key->hash ^= key->forward_pair[i][1] >> 16;
				key->hash ^= key->forward_pair[i][1] << 16;
			}
		}

//#define DEBUG
#ifdef DEBUG
		printf("process_flow_key(): count=%d flags=0x%x hash=0x%x\n",
				scan->packet->pkt_flow_key.pair_count,
				scan->packet->pkt_flow_key.flags,
				scan->packet->pkt_flow_key.hash);
		fflush(stdout);
#endif

	}

}

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    getPairCount
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JFlowKey_getPairCount
(JNIEnv *env, jobject obj) {
	
	flow_key_t *key = (flow_key_t *)jmem_data_get(env, obj);
	if (key == NULL) {
		return 0;
	}

	return (jint) key->pair_count;
}

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    getPair
 * Signature: (IZ)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_packet_JFlowKey_getPair
(JNIEnv *env, jobject obj, jint index, jboolean reverse) {

	flow_key_t *key = (flow_key_t *)jmem_data_get(env, obj);
	if (key == NULL) {
		return 0;
	}
	
	if (reverse) {
		return ((jlong) (key->reverse_pair[index][0]) << 32) |
		(jlong)key->reverse_pair[index][1];
	} else {
		return ((jlong) (key->forward_pair[index][0]) << 32) |
		(jlong)key->forward_pair[index][1];
	}
}

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    getPairP1
 * Signature: (IZ)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JFlowKey_getPairP1
(JNIEnv *env, jobject obj, jint index, jboolean reverse) {

	flow_key_t *key = (flow_key_t *)jmem_data_get(env, obj);
	if (key == NULL) {
		return 0;
	}

	return (reverse)? key->reverse_pair[index][0] : key->forward_pair[index][0];
}

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    getPairP2
 * Signature: (IZ)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JFlowKey_getPairP2
(JNIEnv *env, jobject obj, jint index, jboolean reverse) {

	flow_key_t *key = (flow_key_t *)jmem_data_get(env, obj);
	if (key == NULL) {
		return 0;
	}

	return (reverse)? key->reverse_pair[index][1] : key->forward_pair[index][1];

}

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    hashCode
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JFlowKey_hashCode
(JNIEnv *env, jobject obj) {

	flow_key_t *key = (flow_key_t *)jmem_data_get(env, obj);
	if (key == NULL) {
		return 0;
	}

	return key->hash;
}

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    getHeaderMap
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_packet_JFlowKey_getHeaderMap
(JNIEnv *env, jobject obj) {

	flow_key_t *key = (flow_key_t *)jmem_data_get(env, obj);
	if (key == NULL) {
		return 0;
	}

	return key->header_map;
}

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    getFlags
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JFlowKey_getFlags
  (JNIEnv *env, jobject obj) {
	
	flow_key_t *key = (flow_key_t *)jmem_data_get(env, obj);
	if (key == NULL) {
		return 0;
	}

	return key->flags;	
}

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    match
 * Signature: (Lorg/jnetpcap/packet/JFlowKey;)I
 * 
 * Return: 0 - don't match, 1 = forward, -1 = reverse
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JFlowKey_match
(JNIEnv *env, jobject obj, jobject jFlowKey) {

	flow_key_t *key1 = (flow_key_t *)jmem_data_get(env, obj);
	if (key1 == NULL) {
		return 0;
	}

	flow_key_t *key2 = (flow_key_t *)jmem_data_get(env, jFlowKey);
	if (key2 == NULL) {
		return 0;
	}

#ifdef DEBUG
	printf("equal(): hash1=0x%X hash2=0x%X result=%d\n",
			key1->hash,
			key2->hash,
			key1->hash == key2->hash
	);
	fflush(stdout);
#endif 

	/*
	 * Quick and dirty check if the basics match up, otherwise no point in 
	 * checking further.
	 */
	if ( (key1->hash != key2->hash) || 
			key1->flags != key2->flags || 
			key1->header_map != key2->header_map) {
		return 0;
	}
	

	/*
	 * Now do full check of each pair. Also if key is reversable check if they
	 * match in reverse. Eitherway is a hit.
	 */
	if ( (key1->flags & FLOW_KEY_FLAG_REVERSABLE_PAIRS) > 0) {
		if (memcmp(key1->forward_pair, 
				key2->forward_pair, 
				key1->pair_count * 2) == 0) {
			return 1;
		}
		
		if (memcmp(key1->forward_pair, 
				key2->reverse_pair, 
				key1->pair_count * 2) == 0) {
			
			return -1;
		} else {
			return 0;
		}

	} else {
		if (memcmp(key1->forward_pair, 
				key2->forward_pair, 
				key1->pair_count * 2) == 0) {
			
			return 1;
		} else {
			return 0;
		}
	}
}

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    equal
 * Signature: (Lorg/jnetpcap/packet/JFlowKey;)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jnetpcap_packet_JFlowKey_equal
(JNIEnv *env, jobject obj, jobject jFlowKey) {

	flow_key_t *key1 = (flow_key_t *)jmem_data_get(env, obj);
	if (key1 == NULL) {
		return 0;
	}

	flow_key_t *key2 = (flow_key_t *)jmem_data_get(env, jFlowKey);
	if (key2 == NULL) {
		return 0;
	}

#ifdef DEBUG
	printf("equal(): hash1=0x%X hash2=0x%X result=%d\n",
			key1->hash,
			key2->hash,
			key1->hash == key2->hash
	);
	fflush(stdout);
#endif 

	/*
	 * Quick and dirty check if the basics match up, otherwise no point in 
	 * checking further.
	 */
	if ( (key1->hash != key2->hash) || 
			key1->flags != key2->flags || 
			key1->header_map != key2->header_map) {
		return false;
	}
	

	/*
	 * Now do full check of each pair. Also if key is reversable check if they
	 * match in reverse. Eitherway is a hit.
	 */
	if ( (key1->flags & FLOW_KEY_FLAG_REVERSABLE_PAIRS) > 0) {
		if (memcmp(key1->forward_pair, 
				key2->forward_pair, 
				key1->pair_count * 2) == 0 ||
			memcmp(key1->forward_pair, 
				key2->reverse_pair, 
				key1->pair_count * 2) == 0) {
			
			return JNI_TRUE;
		} else {
			return JNI_FALSE;
		}

	} else {
		if (memcmp(key1->forward_pair, 
				key2->forward_pair, 
				key1->pair_count * 2) == 0) {
			
			return JNI_TRUE;
		} else {
			return JNI_FALSE;
		}
	}
}

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JFlowKey_sizeof
(JNIEnv *, jclass) {

	return (jint) sizeof(flow_key_t);
}

/*
 * Class:     org_jnetpcap_packet_JFlowKey
 * Method:    getId
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JFlowKey_getId
  (JNIEnv *env, jobject obj, jint index) {
	
	flow_key_t *key = (flow_key_t *)jmem_data_get(env, obj);
	if (key == NULL) {
		return 0;
	}

	return (jint) key->id[index];	
}

