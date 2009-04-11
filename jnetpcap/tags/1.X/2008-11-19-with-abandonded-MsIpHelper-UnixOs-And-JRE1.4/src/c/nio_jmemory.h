/* Header for jnetpcap_utils utility methods */

#ifndef _Included_nio_jmemory_h
#define _Included_nio_jmemory_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif
	
#include "export.h"
	
#include <jni.h>

extern	jclass jmemoryClass;

extern	jfieldID jmemoryPhysicalFID;
extern	jfieldID jmemorySizeFID;
extern	jfieldID jmemoryOwnerFID;
extern	jfieldID jmemoryKeeperFID;


// Prototypes
void *getJMemoryPhysical(JNIEnv *env, jobject obj);
void setJMemoryPhysical(JNIEnv *env, jobject obj, jlong value);
void jmemoryCleanup(JNIEnv *env, jobject obj);

#ifdef __cplusplus
}
#endif
#endif
