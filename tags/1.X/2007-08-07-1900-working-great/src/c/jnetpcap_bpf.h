/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_bpf_h
#define _Included_jnetpcap_bpf_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif
	
#include "export.h"
	
#include <jni.h>

extern	jclass bpfProgramClass;

extern	jfieldID bpfProgramPhysicalFID;

// Prototypes
bpf_program *getBpfProgram(JNIEnv *env, jobject obj);
void setBpfProgramPhysical(JNIEnv *env, jobject obj, jlong value);
bpf_program *bpfProgramInitFrom(JNIEnv *env, jobject obj, bpf_program *src);
void freeBpfProgramIfExists(JNIEnv *env, jobject obj);

#ifdef __cplusplus
}
#endif
#endif
