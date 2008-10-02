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

#include "jnetpcap_peered.h"
#include "jnetpcap_utils.h"
#include "export.h"



void *getPeeredPhysical(JNIEnv *env, jobject obj) {
	
	jlong pt = env->GetLongField(obj, peeredPhysicalFID);
	return toPtr(pt);
}

void setPeeredPhysical(JNIEnv *env, jobject obj, jlong value) {
	env->SetLongField(obj, peeredPhysicalFID, value);
}

/*****************************************************************************
 *  These are static and constant unless class file reloads
 */

jclass peeredClass = 0;

jfieldID peeredPhysicalFID = 0;

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_Peered_initIDs
(JNIEnv *env, jclass clazz) {

	jclass c;
	// PcapBpfProgram class
	if ( (peeredClass = c = findClass(env, "org/jnetpcap/Peered")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.Peered");
		return;
	}

	if ( ( peeredPhysicalFID = env->GetFieldID(c, "physical", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field Peered.physical:long");
		return;
	}
}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    initPeer
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_Peered_allocate
  (JNIEnv *env, jobject obj, jint jsize) {
	
	void * mem = malloc((int) jsize);
	if (mem == NULL) {
		throwException(env, OUT_OF_MEMORY_ERROR, "");
		return;
	}
	
	memset(mem, 0, (int) jsize);
	
	setPeeredPhysical(env, obj, toLong(mem));
}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    cleanup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_Peered_cleanup
(JNIEnv *env , jobject obj) {

	void *mem = getPeeredPhysical(env, obj);
	if (mem == NULL) {
		return; // Exception already thrown
	}

	/*
	 * Release the main structure
	 */
	free(mem);
	setPeeredPhysical(env, obj, (jlong) 0);
}
