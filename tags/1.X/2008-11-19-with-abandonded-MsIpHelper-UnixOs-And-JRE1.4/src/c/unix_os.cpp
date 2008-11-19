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
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#endif /*WIN32*/

#include "unix_os.h"
#include "nio_jmemory.h"
#include "jnetpcap_utils.h"
#include "jnetpcap_ids.h"
#include "export.h"
#include "org_jnetpcap_unix_UnixOs.h"



/*****************************************************************************
 *  These are static and constant unless class file reloads
 */

jclass unixOsClass = 0;

/*
 * Class:     org_jnetpcap_unix_UnixOs
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_unix_UnixOs_initIDs
(JNIEnv *env, jclass clazz) {

	jclass c;
	// UnixOs class
	if ( (unixOsClass = c = findClass(env, "org/jnetpcap/unix/UnixOs")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.unix.UnixOs");
		return;
	}
}


#define END_OF_TABLE 	-1L

int translations[] = { 
#ifndef WIN32
	org_jnetpcap_unix_UnixOs_SIOCGIFHWADDR ,SIOCGIFHWADDR,
	org_jnetpcap_unix_UnixOs_SIOCSIFMTU    ,SIOCSIFMTU,
	org_jnetpcap_unix_UnixOs_SIOCGIFMTU    ,SIOCGIFMTU,
	org_jnetpcap_unix_UnixOs_SIOCSIFFLAGS  ,SIOCSIFFLAGS,
	org_jnetpcap_unix_UnixOs_SIOCGIFFLAGS  ,SIOCGIFFLAGS,

	org_jnetpcap_unix_UnixOs_PF_UNIX       ,PF_UNIX,
	org_jnetpcap_unix_UnixOs_PF_INET       ,PF_INET,
	org_jnetpcap_unix_UnixOs_PF_INET6      ,PF_INET6,
	org_jnetpcap_unix_UnixOs_PF_IPX        ,PF_IPX,
	org_jnetpcap_unix_UnixOs_PF_PACKET     ,PF_PACKET,
	
	org_jnetpcap_unix_UnixOs_SOCK_STREAM   ,SOCK_STREAM,
	org_jnetpcap_unix_UnixOs_SOCK_DGRAM    ,SOCK_DGRAM,
	org_jnetpcap_unix_UnixOs_SOCK_RAW      ,SOCK_RAW,
	org_jnetpcap_unix_UnixOs_SOCK_PACKET   ,SOCK_PACKET,
	
	org_jnetpcap_unix_UnixOs_IPPROTO_TCP   ,IPPROTO_TCP,
#endif
	
	org_jnetpcap_unix_UnixOs_PROTOCOL_DEFAULT	,0,
	
	/*
	 * Special END OF TABLE MARK
	 */
	END_OF_TABLE, END_OF_TABLE
};


/*
 * Translate jNetPcap stub constants to actual UNIX contants
 */
int translateConstant(jint src) {
	for (int i = 0; translations[i] != END_OF_TABLE; i += 2) {
		if (translations[i] == src) {
			return translations[i + 1];
		}
	}
	
	return -1;	
}


/*
 * Class:     org_jnetpcap_unix_UnixOs
 * Method:    translateConstant
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_unix_UnixOs_translateConstant
  (JNIEnv *env, jclass clazz, jint jsrc) {

	return translateConstant(jsrc);
}


/*
 * Class:     org_jnetpcap_unix_UnixOs
 * Method:    isSupported
 * Signature: ()Z
 */
JNIEXPORT jboolean Java_org_jnetpcap_unix_UnixOs_isSupported
(JNIEnv *env, jclass clazz) {
	
#ifdef WIN32
	return (jboolean) JNI_FALSE;
#else
	return (jboolean) JNI_TRUE;
#endif
	
}

/*
 * Class:     org_jnetpcap_unix_UnixOs
 * Method:    socket
 * Signature: (III)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_unix_UnixOs_socket
(JNIEnv *env, jclass clazz, jint jdomain, jint jtype, jint jprotocol) {
	
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#else
	int domain = translateConstant(jdomain);
	int type = translateConstant(jtype);
	int protocol = translateConstant(jprotocol);

	return socket((domain == -1)?jdomain:domain, (type == -1)?jtype:type, 
			(protocol == -1)?jprotocol:protocol);
#endif
}

/*
 * Class:     org_jnetpcap_unix_UnixOs
 * Method:    ioctl
 * Signature: (IILjava/lang/Object;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_unix_UnixOs_ioctl__IILjava_lang_Object_2
  (JNIEnv *env, jclass clazz, jint jdescriptor, jint jrequest, jobject jdata) {
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#else
	void *mem = getPeeredPhysical(env, jdata);
	if (mem == NULL) {
		return -1;
	}

	int request = translateConstant(jrequest);

	return ioctl((int) jdescriptor, (request == -1)?jrequest:request, mem);
#endif
	
}

/*
 * Class:     org_jnetpcap_unix_UnixOs
 * Method:    ioctl
 * Signature: (IILorg/jnetpcap/PcapInteger;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_unix_UnixOs_ioctl__IILorg_jnetpcap_PcapInteger_2
  (JNIEnv *env, jclass clazz, jint jdescriptor, jint jrequest, jobject jpcapint) {
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#else
	int request = translateConstant(jrequest);

	int value = (int) env->GetIntField(jpcapint, pcapIntegerValueFID);

	int r = ioctl((int) jdescriptor, (request == -1)?jrequest:request, &value);
	if (r < 0) {
		return r;
	}
	
	env->SetIntField(jpcapint, pcapIntegerValueFID, (jint)value);

	return r;
#endif
}

/*
 * Class:     org_jnetpcap_unix_UnixOs
 * Method:    ioctl
 * Signature: (III)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_unix_UnixOs_ioctl__III
  (JNIEnv *env, jclass clazz, jint jdescriptor, jint jrequest, jint jdata) {
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#else
	int request = translateConstant(jrequest);

	return ioctl((int) jdescriptor, (request == -1)?jrequest:request, (int) jdata);
#endif
	
}

/*
 * Class:     org_jnetpcap_unix_UnixOs
 * Method:    errno
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_unix_UnixOs_errno
  (JNIEnv *env, jclass clazz) {
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#else
	return (jint) errno;
#endif

}

/*
 * Class:     org_jnetpcap_unix_UnixOs
 * Method:    close
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_unix_UnixOs_close
  (JNIEnv *env , jclass clazz, jint jdescriptor) {
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#else
	return close((int) jdescriptor);
#endif
	
}

/*
 * Class:     org_jnetpcap_unix_UnixOs
 * Method:    strerror
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_jnetpcap_unix_UnixOs_strerror
  (JNIEnv *env, jclass clazz, jint jerrnum) {
#ifdef WIN32
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#else
	jstring jmsg = env->NewStringUTF(strerror((int) jerrnum));
	return jmsg;
#endif

}




