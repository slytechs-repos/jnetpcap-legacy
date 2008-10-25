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

#ifdef WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#endif /*WIN32*/

#include "nio_jmemory.h"
#include "jnetpcap_utils.h"
#include "org_jnetpcap_ms_MSIpHelper.h"
#include "export.h"



/*
 * Class:     org_jnetpcap_ms_MSIpHelper
 * Method:    getInterfaceInfo
 * Signature: (Lorg/jnetpcap/ms/MSIpInterfaceInfo;Lorg/jnetpcap/JNumber;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSIpHelper_getInterfaceInfo
  (JNIEnv *env, jclass clazz, jobject jinfo, jobject jsize) {
#ifdef WIN32
	PIP_INTERFACE_INFO info = NULL;
	if (jinfo != NULL) {
		info = (PIP_INTERFACE_INFO) getJMemoryPhysical(env, jinfo);
	}
	DWORD *size = (DWORD *) getJMemoryPhysical(env, jsize);
	if (size == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}
	
//	printf("%p %d %d\n", info, jinfo, *size);
	
	return (jint) GetInterfaceInfo(info, size);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_ms_MSIpHelper
 * Method:    getIfEntry
 * Signature: (Lorg/jnetpcap/ms/MSMibIfRow;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSIpHelper_getIfEntry
  (JNIEnv *env, jclass clazz, jobject jrow) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, jrow);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}
	
	return (jint) GetIfEntry(row);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	
}

/*
 * Class:     org_jnetpcap_ms_MSIpHelper
 * Method:    isSupported
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_jnetpcap_ms_MSIpHelper_isSupported
  (JNIEnv *env, jclass clazz) {
#ifdef WIN32
	return (jboolean) JNI_TRUE;
#else
	return (jboolean) JNI_FALSE;
#endif

}
