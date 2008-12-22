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

extern	jclass jmemoryClass;

extern	jfieldID jmemoryPhysicalFID;
extern	jfieldID jmemoryPhysicalSizeFID;
extern	jfieldID jmemorySizeFID;
extern	jfieldID jmemoryOwnerFID;
extern	jfieldID jmemoryKeeperFID;

extern memory_usage_t memory_usage;

// Prototypes
void *getJMemoryPhysical(JNIEnv *env, jobject obj);
void setJMemoryPhysical(JNIEnv *env, jobject obj, jlong value);
void jmemoryCleanup(JNIEnv *env, jobject obj);


#ifdef __cplusplus
}
#endif
#endif
