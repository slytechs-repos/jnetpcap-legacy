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
#include "org_jnetpcap_unix_UnixOs_IfReq.h"
#include "export.h"

/*
 * Class:     org_jnetpcap_unix_UnixOs_IfReq
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint Java_org_jnetpcap_unix_UnixOs_IfReq_sizeof
(JNIEnv *env, jclass clazz) {
	
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#else
	return (jint) sizeof(struct ifreq);
#endif
	
}

/*
 * Class:     org_jnetpcap_unix_UnixOs_IfReq
 * Method:    ifr_name
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_jnetpcap_unix_UnixOs_IfReq_ifr_1name__
(JNIEnv *env, jobject obj) {
	
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#else

	struct ifreq *mem = (struct ifreq *) getPeeredPhysical(env, obj);
	if (mem == NULL) {
		return NULL; // Exception already thrown
	}

	jstring jstr = env->NewStringUTF(mem->ifr_name);
	if (jstr == NULL) {
		env->DeleteLocalRef(jstr);
		return NULL;
	}
	env->DeleteLocalRef(jstr);
	
	return jstr;
#endif
}

/*
 * Class:     org_jnetpcap_unix_UnixOs_IfReq
 * Method:    ifr_name
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_unix_UnixOs_IfReq_ifr_1name__Ljava_lang_String_2
  (JNIEnv *env, jobject obj, jstring jname) {
	
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return;
#else
	struct ifreq *mem = (struct ifreq *) getPeeredPhysical(env, obj);
	if (mem == NULL) {
		return; // Exception already thrown
	}

	const char* jutf = env->GetStringUTFChars(jname, NULL);
	
	strcpy(mem->ifr_name, jutf);
	env->ReleaseStringUTFChars(jname, jutf);
#endif
}

/*
 * Class:     org_jnetpcap_unix_UnixOs_IfReq
 * Method:    ifr_hwaddr
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_unix_UnixOs_IfReq_ifr_1hwaddr
  (JNIEnv *env, jobject obj) {
	
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#else
	struct ifreq *mem = (struct ifreq *) getPeeredPhysical(env, obj);
	if (mem == NULL) {
		return NULL; // Exception already thrown
	}
	
	jbyteArray ja = env->NewByteArray(6); // MAC length is always 6 bytes
	env->SetByteArrayRegion(ja, 0, 6, (jbyte *)mem->ifr_hwaddr.sa_data);
	
	return ja;
#endif
}

/*
 * Class:     org_jnetpcap_unix_UnixOs_IfReq
 * Method:    ifr_flags
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_unix_UnixOs_IfReq_ifr_1flags__
  (JNIEnv *env, jobject obj) {
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#else
	struct ifreq *mem = (struct ifreq *) getPeeredPhysical(env, obj);
	if (mem == NULL) {
		return -1; // Exception already thrown
	}

	return (jint) mem->ifr_flags;
#endif
}

/*
 * Class:     org_jnetpcap_unix_UnixOs_IfReq
 * Method:    ifr_flags
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_unix_UnixOs_IfReq_ifr_1flags__I
  (JNIEnv *env, jobject obj, jint jflags) {
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return;
#else
	struct ifreq *mem = (struct ifreq *) getPeeredPhysical(env, obj);
	if (mem == NULL) {
		return; // Exception already thrown
	}
	
	mem->ifr_flags = (short int) jflags;
#endif
}

/*
 * Class:     org_jnetpcap_unix_UnixOs_IfReq
 * Method:    ifr_mtu
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_unix_UnixOs_IfReq_ifr_1mtu__
  (JNIEnv *env, jobject obj) {
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#else
	struct ifreq *mem = (struct ifreq *) getPeeredPhysical(env, obj);
	if (mem == NULL) {
		return -1; // Exception already thrown
	}

	return (jint) mem->ifr_mtu;
#endif
	
}

/*
 * Class:     org_jnetpcap_unix_UnixOs_IfReq
 * Method:    ifr_mtu
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_unix_UnixOs_IfReq_ifr_1mtu__I
  (JNIEnv *env, jobject obj, jint jmtu) {
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return;
#else
	struct ifreq *mem = (struct ifreq *) getPeeredPhysical(env, obj);
	if (mem == NULL) {
		return; // Exception already thrown
	}
	
	mem->ifr_mtu = (int) jmtu;
#endif
	
}

