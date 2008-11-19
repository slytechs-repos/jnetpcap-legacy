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
#include "org_jnetpcap_ms_MSIpAdapterIndexMap.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

jclass msIpAdapterIndexMapClass = NULL;
jmethodID msIpAdapterIndexMapMID = 0;

/*
 * Class:     org_jnetpcap_ms_MSIpAdapterIndexMap
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_ms_MSIpAdapterIndexMap_initIDs
  (JNIEnv *env, jclass clazz) {
	
	msIpAdapterIndexMapClass = (jclass) env->NewGlobalRef(clazz);
	
	if ( (msIpAdapterIndexMapMID = env->GetMethodID(clazz, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor org.jnetpcap.MSIpAdapterIndexMap()");
		return;
	}
}

/*
 * Class:     org_jnetpcap_ms_MSIpAdapterIndexMap
 * Method:    index
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSIpAdapterIndexMap_index
  (JNIEnv *env, jobject obj) {
#ifdef WIN32
	PIP_ADAPTER_INDEX_MAP map = (PIP_ADAPTER_INDEX_MAP) getJMemoryPhysical(env, obj);
	if (map == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}
	return (jint) map->Index;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif

}

/*
 * Class:     org_jnetpcap_ms_MSIpAdapterIndexMap
 * Method:    name
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_jnetpcap_ms_MSIpAdapterIndexMap_name
  (JNIEnv *env, jobject obj) {
#ifdef WIN32
	PIP_ADAPTER_INDEX_MAP map = (PIP_ADAPTER_INDEX_MAP) getJMemoryPhysical(env, obj);
	if (map == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return NULL;
	}

	/*
	 * Name is in wide character format. So convert to plain UTF8.
	 */
	int size=WideCharToMultiByte(0, 0, map->Name, -1, NULL, 0, NULL, NULL);
	char utf8[size + 1];
	WideCharToMultiByte(0, 0, map->Name, -1, utf8, size, NULL, NULL);
	
	jstring jstr = env->NewStringUTF((const char *)utf8);
	if (jstr == NULL) {
		env->DeleteLocalRef(jstr);
		return NULL;
	}

	return jstr;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#endif	
}
