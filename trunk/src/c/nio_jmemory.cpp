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
#include "jnetpcap_utils.h"
#include "jnetpcap_ids.h"
#include "org_jnetpcap_nio_JMemory.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions. Private scan function
 * 
 * **************************************************************
 ****************************************************************/

void *getJMemoryPhysical(JNIEnv *env, jobject obj) {

	jlong pt = env->GetLongField(obj, jmemoryPhysicalFID);
	return toPtr(pt);
}

void setJMemoryPhysical(JNIEnv *env, jobject obj, jlong value) {
	/*
	 * Make sure we clean up any previous allocations before we set new ptr
	 * and loose track of the old memory. In essence, this call in this function
	 * makes all JMemory.peer functions call JMemory.cleanup ;)
	 */
	jmemoryCleanup(env, obj);
	
	env->SetLongField(obj, jmemoryPhysicalFID, value);
}

void jmemoryCleanup(JNIEnv *env, jobject obj) {
	Java_org_jnetpcap_nio_JMemory_cleanup(env, obj);	
}

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

jclass jmemoryClass = 0;

jfieldID jmemoryPhysicalFID = 0;
jfieldID jmemorySizeFID = 0;
jfieldID jmemoryOwnerFID = 0;
jfieldID jmemoryKeeperFID = 0;

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_initIDs
(JNIEnv *env, jclass clazz) {

	jclass c;
	
	if ( (jmemoryClass = c = findClass(env, "org/jnetpcap/nio/JMemory")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.JMemory");
		return;
	}

	if ( ( jmemoryPhysicalFID = env->GetFieldID(c, "physical", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.physical:long");
		return;
	}

	if ( ( jmemorySizeFID = env->GetFieldID(c, "size", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.size:int");
		return;
	}

	if ( ( jmemoryOwnerFID = env->GetFieldID(c, "owner", "Z")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.owner:boolean");
		return;
	}

	if ( ( jmemoryKeeperFID = env->GetFieldID(c, "keeper", "Ljava/lang/Object;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.owner:boolean");
		return;
	}
	
//	printf("initIds() - SUCCESS");

}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    initPeer
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_allocate
(JNIEnv *env, jobject obj, jint jsize) {

	void * mem = malloc((int) jsize);
	if (mem == NULL) {
		throwException(env, OUT_OF_MEMORY_ERROR, "");
		return;
	}

	memset(mem, 0, (int) jsize);

	setJMemoryPhysical(env, obj, toLong(mem));
	env->SetBooleanField(obj, jmemoryOwnerFID, JNI_TRUE);
	env->SetIntField(obj, jmemorySizeFID, jsize);
}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    cleanup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_cleanup
(JNIEnv *env, jobject obj) {

	jboolean jowner = env->GetBooleanField(obj, jmemoryOwnerFID);
	void *mem = getJMemoryPhysical(env, obj);
	if (mem != NULL && jowner) {
		/*
		 * Release the main structure
		 */
		free(mem);
	}

	env->SetLongField(obj, jmemoryPhysicalFID, (jlong) 0);
	env->SetBooleanField(obj, jmemoryOwnerFID, JNI_FALSE);
	env->SetIntField(obj, jmemorySizeFID, (jint)0);
	env->SetObjectField(obj, jmemoryKeeperFID, (jobject) NULL);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    nativePeer
 * Signature: (Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_peer
(JNIEnv *env, jobject obj, jobject jbytebuffer) {

	if (jbytebuffer == NULL || byteBufferIsDirectMID == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}
	
	if (env->CallBooleanMethod(jbytebuffer, byteBufferIsDirectMID) == JNI_FALSE) {
		throwException(env, ILLEGAL_ARGUMENT_EXCEPTION,
				"Can only peer with direct ByteBuffer objects");
		return -1;
	}

	
	void *mem = getJMemoryPhysical(env, obj);
	if (mem != NULL) {
		Java_org_jnetpcap_nio_JMemory_cleanup(env, obj);
	}

	jint position = env->CallIntMethod(jbytebuffer, bufferGetPositionMID);
	jint limit = env->CallIntMethod(jbytebuffer, bufferGetLimitMID);

	char *b = (char *)env->GetDirectBufferAddress(jbytebuffer);
	setJMemoryPhysical(env, obj, toLong(b + position));

	env->SetIntField(obj, jmemorySizeFID, (jint) (limit - position));
	env->SetObjectField(obj, jmemoryKeeperFID, jbytebuffer);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferFrom
 * Signature: (Ljava/nio/ByteBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferFrom
  (JNIEnv *env, jobject obj, jobject jbytebuffer, jint jdstOffset, jint jlen) {
	char *dst = (char *)getJMemoryPhysical(env, obj);
	if (dst == NULL || jbytebuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}
	
	jint position = env->CallIntMethod(jbytebuffer, bufferGetPositionMID);
	jint limit = env->CallIntMethod(jbytebuffer, bufferGetLimitMID);
	jsize srcLen = limit - position;
	
	size_t dstLen = env->GetIntField(obj, jmemorySizeFID);
	if (jdstOffset < 0 || jlen > dstLen) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION,"");
	}


	char *b = (char *)env->GetDirectBufferAddress(jbytebuffer);
	jlen = (jlen > dstLen)?dstLen:jlen;
	
	memcpy((void *)(dst + jdstOffset), b + position, jlen);
	
	return jlen;
}



/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferTo
 * Signature: (Lorg/jnetpcap/JMemory;III)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferTo__Lorg_jnetpcap_nio_JMemory_2III
(JNIEnv *env, jobject obj, jobject jdst, jint jsrcOffset, jint jlen, jint jdstOffset) {

	char *src = (char *)getJMemoryPhysical(env, obj);
	if (src == NULL || jdst == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	char *dst = (char *)getJMemoryPhysical(env, jdst);
	if (dst == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	size_t srcLen = env->GetIntField(obj, jmemorySizeFID);
	size_t dstLen = env->GetIntField(jdst, jmemorySizeFID);

	if (jsrcOffset < 0 
			|| jdstOffset < 0 
			|| jsrcOffset + jlen > srcLen 
			|| jdstOffset + jlen > dstLen) {

		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "");
		return -1;
	}
	
	jlen = (dstLen < jlen)?dstLen:jlen;

	memcpy((void *)(dst + jdstOffset), (void *)(src + jsrcOffset), jlen);
	
	return jlen;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferTo
 * Signature: (Ljava/nio/ByteBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferTo__Ljava_nio_ByteBuffer_2II
(JNIEnv *env, jobject obj, jobject jbytebuffer, jint jsrcOffset, jint jlen) {

	char *src = (char *)getJMemoryPhysical(env, obj);
	if (src == NULL || jbytebuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}
	
	jint position = env->CallIntMethod(jbytebuffer, bufferGetPositionMID);
	jint limit = env->CallIntMethod(jbytebuffer, bufferGetLimitMID);
	jsize dstLen = limit - position;
	
	size_t srcLen = env->GetIntField(obj, jmemorySizeFID);
	if (jsrcOffset < 0 || jlen > srcLen) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION,"");
	}


	char *b = (char *)env->GetDirectBufferAddress(jbytebuffer);
	jlen = (jlen > dstLen)?dstLen:jlen;
	
	memcpy(b + position, (void *)(src + jsrcOffset), jlen);
	
	return jlen;
}

