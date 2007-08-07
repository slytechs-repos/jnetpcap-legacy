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

#include "winpcap_ext.h"
#include "jnetpcap_utils.h"

jclass winPcapClass = 0;

jmethodID winPcapConstructorMID = 0;

/*
 * Function: testExtensionSupport
 * Description: Tests if WinPcap extensions is available on this platform.
 * Return: JNI_TRUE if yes, otherwise JNI_FALSE
 */
jboolean testExtensionSupport() {
#ifdef WIN32
	return (jboolean)JNI_TRUE;
#else
	return (jboolean)JNI_FALSE;
#endif
}

/*
 * Function: testExtensionSupportAndThrow
 * Description: checks if winpcap ext is supported and throws exception if not.
 * Return: JNI_TRUE if yes, otherwise JNI_FALSE
 */
jboolean testExtensionSupportAndThrow(JNIEnv *env) {
	
	if (testExtensionSupport() == JNI_FALSE) {
		throwException(env, UNSUPPORTED_OPERATION_EXCEPTION, "");
		
		return JNI_FALSE;
	} else {
		return JNI_TRUE;
	}
}


/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    initIDs
 * Signature: ()V
 */
EXTERN void Java_org_jnetpcap_winpcap_WinPcap_initIDs(JNIEnv *env, jclass jclazz) {
	winPcapClass = (jclass) env->NewGlobalRef(jclazz); // This one is easy
	
	/*
	 * Check if extensions are supported, if not, just quietly exit. Users
	 * must use WinPcap.isSupported() to check if extensions are availabe.
	 * Therefore we must let the WinPcap class finish loading normally, just
	 * left in uninitialized state. All static methods check and throw exception
	 * if not supported and called.
	 */
	if (testExtensionSupport() == JNI_FALSE) {
		return;
	}

	if ( (winPcapConstructorMID = env->GetMethodID(jclazz, "<init>", "()V"))
			== NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor WinPcap.WinPcap()");
		return;
	}

}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    isSupported
 * Signature: ()Z
 */
EXTERN jboolean JNICALL Java_org_jnetpcap_winpcap_WinPcap_isSupported
(JNIEnv *env , jclass jclazz) {

	return testExtensionSupport();
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    openDead
 * Signature: (II)Lorg/jnetpcap/winpcap/WinPcap;
 */
EXTERN jobject JNICALL Java_org_jnetpcap_winpcap_WinPcap_openDead
(JNIEnv *env, jclass clazz, jint jlinktype, jint jsnaplen) {
	
	/*
	 * Make sure extensions are supported, these methods will compile on
	 * non WinPcap based systems, so we rely on exception handling to prevent
	 * people from using these methods.
	 */
	if (testExtensionSupportAndThrow(env) == JNI_FALSE) {
		return NULL; // Exception already thrown
	}

	pcap_t *p = pcap_open_dead(jlinktype, jsnaplen);
	if (p == NULL) {
		return NULL;
	}

	/*
	 * Use a no-arg constructor and initialize 'physical' field using
	 * special JNI priviledges.
	 */
	jobject obj = env->NewObject(clazz, winPcapConstructorMID);
	setPhysical(env, obj, toLong(p));
	
	return obj;
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    openLive
 * Signature: (Ljava/lang/String;IIILjava/lang/StringBuilder;)Lorg/jnetpcap/winpcap/WinPcap;
 */
EXTERN jobject JNICALL Java_org_jnetpcap_winpcap_WinPcap_openLive
(JNIEnv *env, jclass clazz, jstring jdevice, jint jsnaplen, jint jpromisc, jint jtimeout,
		jobject jerrbuf) {

	/*
	 * Make sure extensions are supported, these methods will compile on
	 * non WinPcap based systems, so we rely on exception handling to prevent
	 * people from using these methods.
	 */
	if (testExtensionSupportAndThrow(env) == JNI_FALSE) {
		return NULL; // Exception already thrown
	}

	if (jdevice == NULL || jerrbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return NULL;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = '\0'; // Reset the buffer;

	const char *device = env->GetStringUTFChars(jdevice, 0);

	//	printf("device=%s snaplen=%d, promisc=%d timeout=%d\n",
	//			device, jsnaplen, jpromisc, jtimeout);

	pcap_t *p = pcap_open_live(device, jsnaplen, jpromisc, jtimeout, errbuf);
	setString(env, jerrbuf, errbuf); // Even if no error, could have warning msg
	if (p == NULL) {
		return NULL;
	}

	/*
	 * Use a no-arg constructor and initialize 'physical' field using
	 * special JNI priviledges.
	 */
	jobject obj = env->NewObject(clazz, winPcapConstructorMID);
	setPhysical(env, obj, toLong(p));

	return obj;
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    openOffline
 * Signature: (Ljava/lang/String;Ljava/lang/StringBuilder;)Lorg/jnetpcap/winpcap/WinPcap;
 */
EXTERN jobject JNICALL Java_org_jnetpcap_winpcap_WinPcap_openOffline
(JNIEnv *env, jclass clazz, jstring jfname, jobject jerrbuf) {
	
	/*
	 * Make sure extensions are supported, these methods will compile on
	 * non WinPcap based systems, so we rely on exception handling to prevent
	 * people from using these methods.
	 */
	if (testExtensionSupportAndThrow(env) == JNI_FALSE) {
		return NULL; // Exception already thrown
	}

	if (jfname == NULL || jerrbuf == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, NULL);
		return NULL;
	}
	
	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = '\0'; // Reset the buffer;
	const char *fname = env->GetStringUTFChars(jfname, 0);

	pcap_t *p = pcap_open_offline(fname, errbuf);
	if (p == NULL) {
		setString(env, jerrbuf, errbuf);
		return NULL;
	}

	/*
	 * Use a no-arg constructor and initialize 'physical' field using
	 * special JNI priviledges.
	 */
	jobject obj = env->NewObject(clazz, winPcapConstructorMID);
	setPhysical(env, obj, toLong(p));
	
	return obj;
}

/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    setBuff
 * Signature: (I)I
 */
EXTERN jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_setBuff
(JNIEnv *env, jobject obj, jint value) {

	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return -1; // Exception already thrown
	}

	return pcap_setbuff(p, value);
}
/*
 * Class:     org_jnetpcap_winpcap_WinPcap
 * Method:    setMode
 * Signature: (I)I
 */
EXTERN jint JNICALL Java_org_jnetpcap_winpcap_WinPcap_setMode
(JNIEnv *env, jobject obj, jint value) {

	pcap_t *p = getPcap(env, obj);
	if (p == NULL) {
		return -1; // Exception already thrown
	}

	return pcap_setmode(p, value);
}
