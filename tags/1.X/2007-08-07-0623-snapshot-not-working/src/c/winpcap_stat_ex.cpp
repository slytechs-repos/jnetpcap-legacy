/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Main WinPcap extensions file for jNetPcap.
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
#else
#include <Win32-Extensions.h>
#endif /*WIN32*/

#include "jnetpcap_bpf.h"
#include "winpcap_ext.h"
#include "jnetpcap_utils.h"

jclass pcapStatExClass = 0;

jmethodID pcapStatExConstructorMID = 0;

int FIELD_COUNT = 21;
char *fieldNames[] = {
		"rxPackets",
		"txPackets",
		"rxBytes",
		"txBytes",
		"rxErrors",
		"txErrors",
		"rxDropped",
		"txDropped",
		"multicast",
		"collisions",
		"rxLengthErrors",
		"rxOverErrors",
		"rxCrcErrors",
		"rxFrameErrors",
		"rxFifoErrors",
		"rxMissedErrors",
		"txAbortedErrors",
		"txCarrierErrors",
		"txFifoErrors",
		"txHeartbeatErrors",
		"txWindowErrors",
};

jfieldID *fieldIDs = NULL;

/*
 * Function: new newPcapStatEx()
 * Description: allocates a new PcapStatEx object
 */
EXTERN jobject newPcapStatEx(JNIEnv *env) {
	
	jobject jstats = env->NewObject(pcapStatExClass, pcapStatExConstructorMID);
	return jstats;
}

/*
 * Function: setPcapStatEx
 * Description: copies from stat_ex structure all the members into a PcapStatEx
 *              object.
 */
EXTERN void setPcapStatEx(JNIEnv *env, jobject jstats, 
		struct pcap_stat_ex *stats, int size) {
	size = size / 8;
	long *p = (long *)stats;
	
	// Each field is a long, so iterate and assign by array lookup
	for (int i = 0; i < size; i += 1) {
		env->SetLongField(jstats, fieldIDs[i], (jlong) p[i]);
	}
	
	// Fill any remaining fields with -1, to mark fields that received no value
	for (int i = size; i < FIELD_COUNT; i += 1) {
		env->SetLongField(jstats, fieldIDs[i], (jlong) -1);
	}

}

/*
 * Class:     org_jnetpcap_winpcap_PcapStatEx
 * Method:    initIDs
 * Signature: ()V
 */
EXTERN void JNICALL Java_org_jnetpcap_winpcap_PcapStatEx_initIDs
  (JNIEnv *env, jclass clazz) {
	
	if (fieldIDs != NULL) {
		free(fieldIDs);
	}
	
	fieldIDs = (jfieldID *)malloc(sizeof(jfieldID) * FIELD_COUNT);
	
	if (pcapStatExClass != NULL) {
		env->DeleteGlobalRef(pcapStatExClass);
	}
	pcapStatExClass = (jclass) env->NewGlobalRef(clazz);
	
	for (int i = 0; i < FIELD_COUNT; i ++) {
		if ( (fieldIDs[i] = env->GetFieldID(clazz, fieldNames[i], "J")) == 0) {
			throwException(env, NO_SUCH_FIELD_EXCEPTION,
					fieldNames[i]);
		}
	}
	
}

