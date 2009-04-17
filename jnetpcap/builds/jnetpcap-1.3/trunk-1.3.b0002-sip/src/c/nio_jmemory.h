/* Header for jnetpcap_utils utility methods */

#ifndef _Included_nio_jmemory_h
#define _Included_nio_jmemory_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif
	
#include <stdint.h>
#include "export.h"
	
#include <jni.h>
	
typedef struct memory_usage_t {
	uint64_t total_allocated;
	uint64_t total_deallocated;
		
	uint64_t total_allocate_calls;
	uint64_t total_deallocate_calls;
	
	uint64_t seg_0_255_bytes;
	uint64_t seg_256_or_above_bytes;		
} memory_usage_t;

typedef struct jni_global_ref_t {
	int count; // Number of references held
	jobject reference[]; // array of references held
} jni_global_ref_t;


extern	jclass jmemoryClass;
extern	jclass jreferenceClass;

extern  jmethodID jreferenceConstVoidMID;
extern  jmethodID jmemoryToDebugStringMID;

extern	jfieldID jmemoryPhysicalFID;
extern	jfieldID jmemoryPhysicalSizeFID;
extern	jfieldID jmemorySizeFID;
extern	jfieldID jmemoryOwnerFID;
extern	jfieldID jmemoryKeeperFID;
extern	jfieldID jmemoryReferencesFID;

extern memory_usage_t memory_usage;

// Prototypes
void *getJMemoryPhysical(JNIEnv *env, jobject obj);
void setJMemoryPhysical(JNIEnv *env, jobject obj, jlong value);
void jmemoryCleanup(JNIEnv *env, jobject obj);
jobject jmemoryRefCreate(JNIEnv *env, jobject jmemory, jobject local_ref);
void jmemoryRefRelease(JNIEnv *env, jobject jmemory, jobject global_ref);

jobject jreferenceCreate(JNIEnv *env, jobject jref, jobject local_ref);
void jreferenceRelease(JNIEnv *env, jobject jref, jobject global_ref);


#ifdef __cplusplus
}
#endif
#endif
