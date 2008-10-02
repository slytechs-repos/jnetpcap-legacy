/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_peered_h
#define _Included_jnetpcap_peered_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif
	
#include "export.h"
	
#include <jni.h>

extern	jclass peeredClass;

extern	jfieldID peeredPhysicalFID;

// Prototypes
void *getPeeredPhysical(JNIEnv *env, jobject obj);
void setPeeredPhysical(JNIEnv *env, jobject obj, jlong value);

#ifdef __cplusplus
}
#endif
#endif
