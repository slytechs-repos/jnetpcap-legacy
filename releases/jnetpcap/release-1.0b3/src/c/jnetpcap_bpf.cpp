/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */
#include "export.h"

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

#include "jnetpcap_bpf.h"
#include "jnetpcap_utils.h"
#include "jnetpcap_ids.h"



bpf_program *getBpfProgram(JNIEnv *env, jobject obj) {
	jlong pt = env->GetLongField(obj, bpfProgramPhysicalFID);

	if (pt == 0) {
		throwException(env, ILLEGAL_STATE_EXCEPTION,
				"BpfProgram already deallocated (bpf_program).");

		return NULL;
	}

	bpf_program *p = (bpf_program *) toPtr(pt);

	return p;
}

void freeBpfProgramIfExists(JNIEnv *env, jobject obj) {
	jlong pt = env->GetLongField(obj, bpfProgramPhysicalFID);

	if (pt == 0) {
		return;
	}

	bpf_program *p = (bpf_program *) toPtr(pt);

	free(p->bf_insns);
	free(p);

	setBpfProgramPhysical(env, obj, (jlong) 0);

	return;
}

void setBpfProgramPhysical(JNIEnv *env, jobject obj, jlong value) {
	env->SetLongField(obj, bpfProgramPhysicalFID, value);
}

bpf_program *bpfProgramInitFrom(JNIEnv *env, jobject obj, bpf_program *src) {
	bpf_program *dst = (bpf_program *)malloc(sizeof(bpf_program));
	dst->bf_insns = (bpf_insn *)malloc(src->bf_len * 8); // Each inst is 8 bytes

	memcpy(dst, src, sizeof(bpf_program));
	memcpy(dst->bf_insns, src->bf_insns, src->bf_len * 8);

	setBpfProgramPhysical(env, obj, toLong(dst));

	return dst;
}

/*****************************************************************************
 *  These are static and constant unless class file reloads
 */

jclass bpfProgramClass = 0;

jfieldID bpfProgramPhysicalFID = 0;

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapBpfProgram_initIDs
(JNIEnv *env, jclass clazz) {

	jclass c;
	// PcapBpfProgram class
	if ( (bpfProgramClass = c = findClass(env, "org/jnetpcap/PcapBpfProgram")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapBpfProgram");
		return;
	}

	if ( ( bpfProgramPhysicalFID = env->GetFieldID(c, "physical", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapBpfProgram.physical:long");
		return;
	}
}


/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    cleanup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapBpfProgram_cleanup
(JNIEnv *env , jobject obj) {

	freeBpfProgramIfExists(env, obj);
}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    initFromArray
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapBpfProgram_initFromArray
(JNIEnv *env, jobject obj, jbyteArray jinst) {

}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    initFromBuffer
 * Signature: (Ljava/nio/ByteBuffer;II)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapBpfProgram_initFromBuffer
(JNIEnv *env , jobject obj, jobject jbuf, jint jstart, jint jlen) {

}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    getInstructionCount
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapBpfProgram_getInstructionCount
(JNIEnv *env, jobject jbpf) {

	bpf_program *b = getBpfProgram(env, jbpf);
	if (b == NULL) {
		return -1; // Exception already thrown
	}

	return (jint)b->bf_len;
}

/*
 * Class:     org_jnetpcap_PcapBpfProgram
 * Method:    getInstruction
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_PcapBpfProgram_getInstruction
(JNIEnv *env, jobject jbpf, jint index) {

	bpf_program *b = getBpfProgram(env, jbpf);
	if (b == NULL) {
		return -1; // Exception already thrown
	}

	// Check bounds
	if (index < 0 || index >= b->bf_len) {
		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "index must be 0 < index <= len");
		return -1;
	}

	jlong *i = (jlong *)b->bf_insns;
	
	return i[index];
}
