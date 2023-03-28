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

#include <jni.h>

#include "org_jnetpcap_nap_Nap.h"
#include "org_jnetpcap_nap_NapBlock_State.h"
#include "nio_jmemory.h"
#include "jnetpcap_exception.h"
#include "export.h"
#include "nap.h"

/*
 * Class:     org_jnetpcap_nap_Nap
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nap_Nap_sizeof
(JNIEnv *env, jclass clazz) {

	return (jint) sizeof(nap_t);
}

/*
 * Class:     org_jnetpcap_nap_Nap
 * Method:    nativeOpen
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nap_Nap_nativeOpen
(JNIEnv *env, jobject obj, jstring file, jstring mode, jobject errbuf) {

}

/*
 * Class:     org_jnetpcap_nap_NapBlock_State
 * Method:    allocBlock
 * Signature: (Lorg/jnetpcap/nap/NapBlock;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nap_NapBlock_00024State_allocBlock
(JNIEnv *env, jobject block_state, jobject jnap, jobject parent) {

	nap_t *nap = (nap_t *)getJMemoryPhysical(env, jnap);
	if (nap == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return;
	}

	block_t *block = nap_alloc_block(nap, NAP_DEFAULT_BLOCK_SIZE);
	if (block == NULL) {
		throwException(env, OUT_OF_MEMORY_ERROR, "");
		return;
	}
	
	jmemoryPeer(env, block_state, block, sizeof(block_t), block_state);
	jmemoryPeer(env, parent, block->b_header, NAP_DEFAULT_BLOCK_SIZE, block_state);
}

/*
 * Class:     org_jnetpcap_nap_NapBlock_State
 * Method:    cleanup
 * Signature: (Lorg/jnetpcap/nap/NapBlock;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nap_NapBlock_00024State_cleanup
(JNIEnv *env, jobject obj, jobject parent) {

	jmemoryCleanup(env, obj);    // Block.State
	jmemoryCleanup(env, parent); // Block
}

