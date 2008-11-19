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
#include "jnetpcap_ids.h"
#include "org_jnetpcap_ms_MSIpInterfaceInfo.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/


/*
 * Class:     org_jnetpcap_ms_MSIpInterfaceInfo
 * Method:    numAdapters
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_ms_MSIpInterfaceInfo_numAdapters
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PIP_INTERFACE_INFO info = (PIP_INTERFACE_INFO) getJMemoryPhysical(env, obj);
	if (info == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) info->NumAdapters;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif

}

/*
 * Class:     org_jnetpcap_ms_MSIpInterfaceInfo
 * Method:    adapter
 * Signature: (I)Lorg/jnetpcap/ms/MSIpAdapterIndexMap;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_ms_MSIpInterfaceInfo_adapter
(JNIEnv *env, jobject obj, jint jindex) {
#ifdef WIN32
	PIP_INTERFACE_INFO info = (PIP_INTERFACE_INFO) getJMemoryPhysical(env, obj);
	if (info == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return NULL;
	}

	if (msIpAdapterIndexMapClass == NULL || msIpAdapterIndexMapMID == NULL) {
		throwException(env, ILLEGAL_STATE_EXCEPTION, 
				"MSIpAdapterIndexMap class found but not JNI initialized. " 
				"adapter() method needs to create and return an " 
				"instance of this class. Make sure that MSIpAdapterIndexMap class "
				"is referenced/loaded in java prior to this call");
		return NULL;
	}

	if (jindex >= info->NumAdapters || jindex < 0) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, NULL);
		return NULL;
	}

//	printf("%p %p\n", msIpAdapterIndexMapClass, msIpAdapterIndexMapMID);

	jobject jmap = env->NewObject(msIpAdapterIndexMapClass, 
			msIpAdapterIndexMapMID);
	if (jmap == NULL) {
		return NULL; // Out of memory
	}
	
	setJMemoryPhysical(env, jmap, toLong((void *) &info->Adapter[(int)jindex]));
	
	return jmap;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#endif

}

