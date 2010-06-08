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
extern	jclass jmemoryPoolClass;

extern  jmethodID jreferenceConstVoidMID;
extern  jmethodID jmemoryToDebugStringMID;

extern	jfieldID jmemoryPhysicalFID;
extern	jfieldID jmemoryPhysicalSizeFID;
extern	jfieldID jmemorySizeFID;
extern	jfieldID jmemoryOwnerFID;
extern	jfieldID jmemoryKeeperFID;
extern	jfieldID jmemoryReferencesFID;
extern	jobject  jmemoryPOINTER_CONST; // JMemory.POINTER constant reference

extern jmethodID jmemoryPoolAllocateExclusiveMID;
extern jmethodID jmemoryPoolDefaultMemoryPoolMID;

extern jobject defaultMemoryPool;

extern memory_usage_t memory_usage;

// Prototypes
void init_jmemory(JNIEnv *env);
void *getJMemoryPhysical(JNIEnv *env, jobject obj);
void setJMemoryPhysical(JNIEnv *env, jobject obj, jlong value);
void jmemoryCleanup(JNIEnv *env, jobject obj);
jobject jmemoryRefCreate(JNIEnv *env, jobject jmemory, jobject local_ref);
void jmemoryRefRelease(JNIEnv *env, jobject jmemory, jobject global_ref);

size_t getJMemorySize(JNIEnv *env, jobject obj);
jobject jreferenceCreate(JNIEnv *env, jobject jref, jobject local_ref);
void jreferenceRelease(JNIEnv *env, jobject jref, jobject global_ref);
jint jmemoryPeer(JNIEnv *env, jobject obj, const void *ptr, size_t length, jobject owner);

char *jmemoryPoolAllocate(JNIEnv *env, size_t size, jobject *obj_ref);
void jmemoryResize(JNIEnv *env, jobject obj, size_t size);
char *jmemoryAllocate(JNIEnv *env, size_t size, jobject obj);
char *jmemoryToDebugString(JNIEnv *env, jobject obj, char *buf);


#ifdef __cplusplus
}
#endif
#endif
