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
#include "org_jnetpcap_ms_MSMibIfRow.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_sizeof
(JNIEnv *env, jclass clazz) {
#ifdef WIN32
	return sizeof(MIB_IFROW);
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    wszName
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_jnetpcap_ms_MSMibIfRow_wszName
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return NULL;
	}
	
	printf("wszName=%ws\n", row->wszName);

	jstring jstr = env->NewStringUTF((const char *)row->wszName);
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

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwIndex
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwIndex__
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwIndex;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	
}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwIndex
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwIndex__I
(JNIEnv *env, jobject obj, jint jindex) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return;
	}
	
	row->dwIndex = (int) jindex;

	return;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwType
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwType
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwType;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwMtu
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwMtu
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwMtu;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwSpeed
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwSpeed
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwSpeed;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwPhysAddrLen
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwPhysAddrLen
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwPhysAddrLen;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    bPhysAddr
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_ms_MSMibIfRow_bPhysAddr
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return NULL;
	}
	
	jbyteArray ja = env->NewByteArray(6); // MAC length is always 6 bytes
	env->SetByteArrayRegion(ja, 0, 6, (jbyte *)row->bPhysAddr);
	return ja;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return NULL;
#endif	
}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwAdminStatus
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwAdminStatus
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwAdminStatus;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwOperStatus
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwOperStatus
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwOperStatus;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwLastChange
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwLastChange
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwLastChange;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwInUcastPkts
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwInUcastPkts
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwInUcastPkts;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwInNUcastPkts
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwInNUcastPkts
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwInNUcastPkts;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwInDiscards
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwInDiscards
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwInDiscards;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwInErrors
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwInErrors
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwInErrors;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwInUnknownProtos
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwInUnknownProtos
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwInUnknownProtos;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwOutOctets
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwOutOctets
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwOutOctets;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwOutUcastPkts
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwOutUcastPkts
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwOutUcastPkts;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwOutNUcastPkts
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwOutNUcastPkts
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwOutNUcastPkts;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwOutDiscards
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwOutDiscards
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwOutDiscards;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwOutErrors
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwOutErrors
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwOutErrors;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwOutQLen
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwOutQLen
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwOutQLen;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    dwDescrLen
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_ms_MSMibIfRow_dwDescrLen
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return -1;
	}

	return (jint) row->dwDescrLen;
#else
	throwException(env, PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION, NULL);
	return -1;
#endif	

}

/*
 * Class:     org_jnetpcap_ms_MSMibIfRow
 * Method:    bDescr
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_jnetpcap_ms_MSMibIfRow_bDescr
(JNIEnv *env, jobject obj) {
#ifdef WIN32
	PMIB_IFROW row = (PMIB_IFROW) getJMemoryPhysical(env, obj);
	if (row == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return NULL;
	}
	
	/*
	 * Copy string to temporary UTF8 buffer
	 */
	char b[row->dwDescrLen + 1];
	for (int i = 0; i < row->dwDescrLen; i ++) {
		b[i] = row->bDescr[i];
	}
	b[row->dwDescrLen] = '\0';

	jstring jstr = env->NewStringUTF((const char *)b);
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

