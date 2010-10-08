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

#include "nio_jmemory.h"
#include "jnetpcap_utils.h"
#include "jnetpcap_ids.h"
#include "org_jnetpcap_nio_JMemory.h"
#include "org_jnetpcap_nio_JReference.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 *
 * NON Java declared native functions. Private scan function
 *
 * **************************************************************
 ****************************************************************/


/****************************************************************
 * **************************************************************
 *
 * Java declared native functions for jMemory class
 *
 * **************************************************************
 ****************************************************************/

jclass jmemoryClass = 0;
jclass jreferenceClass = 0;
jclass jmemoryPoolClass = 0;

jmethodID jreferenceConstVoidMID = 0;
jmethodID jmemoryToDebugStringMID = 0;

jfieldID jmemoryPhysicalFID = 0;
jfieldID jmemoryPhysicalSizeFID = 0;
jfieldID jmemorySizeFID = 0;
jfieldID jmemoryOwnerFID = 0;
jfieldID jmemoryKeeperFID = 0;
jfieldID jmemoryReferencesFID = 0;
jfieldID jmemoryPOINTERFID = 0;

jobject jmemoryPOINTER_CONST;

jmethodID jmemoryPoolAllocateExclusiveMID = 0;
jmethodID jmemoryPoolDefaultMemoryPoolMID = 0;

jobject defaultMemoryPool = NULL;


/*
 * Global memory usage statistics for jmemory class
 */
memory_usage_t memory_usage;

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_initIDs
(JNIEnv *env, jclass clazz) {

	memset(&memory_usage, 0, sizeof(memory_usage_t));

	jclass c;

	if ( (jmemoryClass = c = findClass(env, "org/jnetpcap/nio/JMemory")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.JMemory");
		return;
	}

	if ( ( jmemoryPhysicalFID = env->GetFieldID(c, "physical", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.physical:long");
		return;
	}

	if ( ( jmemorySizeFID = env->GetFieldID(c, "size", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.size:int");
		return;
	}

	if ( ( jmemoryPhysicalSizeFID = env->GetFieldID(c, "physicalSize", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.physicalSize:int");
		return;
	}

	if ( ( jmemoryOwnerFID = env->GetFieldID(c, "owner", "Z")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.owner:boolean");
		return;
	}

	if ( ( jmemoryKeeperFID = env->GetFieldID(c, "keeper", "Ljava/lang/Object;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.keeper:Object");
		return;
	}

	if ( ( jmemoryReferencesFID = env->GetFieldID(c, "references", "Lorg/jnetpcap/nio/JReference;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.references:JReference");
		fprintf(stderr, "Unable to initialize field JMemory.references:JReference");
		return;
	}

	if ( ( jmemoryToDebugStringMID = env->GetMethodID(c, "toDebugString", "()Ljava/lang/String;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize method JMemory.toDebugString():String");
		fprintf(stderr, "Unable to initialize method JMemory.toDebugString():String");
		return;
	}


	if ( (jreferenceClass = c = findClass(env, "org/jnetpcap/nio/JReference")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.JReference");
		fprintf(stderr, "Unable to initialize class org.jnetpcap.JReference");
		return;
	}

	if ( ( jreferenceConstVoidMID = env->GetMethodID(jreferenceClass, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize method JReference.<init>():void");
		fprintf(stderr, "Unable to initialize method JReference.<init>():void");
		return;
	}

	jclass typeClass;
	if ( (typeClass = findClass(env, "org/jnetpcap/nio/JMemory$Type")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to find class JMemory.Type");
		fprintf(stderr, "Unable to find class JMemory.Type");
		return;
	}

	if ( ( jmemoryPOINTERFID = env->GetStaticFieldID(
							typeClass, "POINTER",
							"Lorg/jnetpcap/nio/JMemory$Type;")) == NULL) {

		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JMemory.Type.POINTER:JMemory.Type");
		fprintf(stderr, "Unable to initialize field JMemory.Type.POINTER:JMemory.Type");
		return;
	}

	jmemoryPOINTER_CONST = env->NewGlobalRef(
			env->GetStaticObjectField(typeClass, jmemoryPOINTERFID));

	if ( (jmemoryPoolClass = c = findClass(env, "org/jnetpcap/nio/JMemoryPool")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.JMemoryPool");
		return;
	}

	if ( ( jmemoryPoolAllocateExclusiveMID = env->GetMethodID(c, "allocateExclusive", "(I)Lorg/jnetpcap/nio/JMemory;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize method JMemoryPool.allocateExlusive():JMemory");
		fprintf(stderr, "Unable to initialize method JMemoryPool.allocateExlusive():JMemory");
		return;
	}

	if ( ( jmemoryPoolDefaultMemoryPoolMID = env->GetStaticMethodID(c, "defaultMemoryPool", "()Lorg/jnetpcap/nio/JMemoryPool;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize method JMemoryPool.defaultMemoryPool():JMemoryPool");
		fprintf(stderr, "Unable to initialize method JMemoryPool.defaultMemoryPool():JMemoryPool");
		return;
	}


#ifdef DEBUG
	printf("initIds() - SUCCESS");
#endif

	/*
	 * Now initialize some jmemory state that is needed for global memory allocation
	 */
	init_jmemory(env);
}

void init_jmemory(JNIEnv *env) {

	defaultMemoryPool = env->CallStaticObjectMethod(jmemoryPoolClass, jmemoryPoolDefaultMemoryPoolMID);

	if (defaultMemoryPool == NULL) {
		fprintf(stderr, "unable to get default memory pool\n");
		fflush(stderr);
	}
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocateCalls
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocateCalls(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_allocate_calls;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocated
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocated(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_allocated;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocatedSegments0To255Bytes
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocatedSegments0To255Bytes(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.seg_0_255_bytes;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocatedSegments256OrAbove
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocatedSegments256OrAbove(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.seg_256_or_above_bytes;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalDeAllocateCalls
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalDeAllocateCalls(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_deallocate_calls;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalDeAllocated
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalDeAllocated(
		JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_deallocated;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    allocate
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_allocate
(JNIEnv *env, jobject obj, jint jsize) {

	jmemoryAllocate(env, (size_t) jsize, obj);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    cleanup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_cleanup
(JNIEnv *env, jobject obj) {

	jmemoryCleanup(env, obj);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    nativePeer
 * Signature: (Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_peer(JNIEnv *env,
		jobject obj, jobject jbytebuffer) {

	if (jbytebuffer == NULL || byteBufferIsDirectMID == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	if (env->CallBooleanMethod(jbytebuffer, byteBufferIsDirectMID) == JNI_FALSE) {
		throwException(env, ILLEGAL_ARGUMENT_EXCEPTION,
				"Can only peer with direct ByteBuffer objects");
		return -1;
	}

	void *mem = getJMemoryPhysical(env, obj);
	if (mem != NULL) {
		Java_org_jnetpcap_nio_JMemory_cleanup(env, obj);
	}

	jint position = env->CallIntMethod(jbytebuffer, bufferGetPositionMID);
	jint limit = env->CallIntMethod(jbytebuffer, bufferGetLimitMID);

	char *b = (char *) env->GetDirectBufferAddress(jbytebuffer);
	setJMemoryPhysical(env, obj, toLong(b + position));

	env->SetIntField(obj, jmemorySizeFID, (jint)(limit - position));
	env->SetObjectField(obj, jmemoryKeeperFID, jbytebuffer);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferFrom
 * Signature: ([BIII)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferFrom___3BIII(
		JNIEnv *env, jobject obj, jbyteArray sa, jint soffset, jint len,
		jint doffset) {

	jbyte *src = (jbyte *) getJMemoryPhysical(env, obj);
	if (src == NULL || sa == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	env->GetByteArrayRegion(sa, soffset, len, (src + doffset));

	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferFromDirect
 * Signature: (Ljava/nio/ByteBuffer;I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferFromDirect(
		JNIEnv *env, jobject obj, jobject jbytebuffer, jint offset) {

	char *dst = (char *) getJMemoryPhysical(env, obj);
	if (dst == NULL || jbytebuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	jint position = env->CallIntMethod(jbytebuffer, bufferGetPositionMID);
	jint limit = env->CallIntMethod(jbytebuffer, bufferGetLimitMID);
	jsize len = limit - position;

	size_t size = env->GetIntField(obj, jmemorySizeFID);

#ifdef DEBUG
	printf("JMemory.transferFrom(ByteBuffer): position=%d limit=%d len=%d\n",
			position, limit, len);
	fflush(stdout);
#endif

	if (size < len) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}

	char *b = (char *) env->GetDirectBufferAddress(jbytebuffer);

	memcpy((void *) (dst + offset), b + position, len);

	env->CallObjectMethod(jbytebuffer, bufferSetPositionMID, position + len);

	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferTo
 * Signature: ([BIII)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferTo___3BIII(
		JNIEnv *env, jobject obj, jbyteArray da, jint soffset, jint len,
		jint doffset) {

	jbyte *src = (jbyte *) getJMemoryPhysical(env, obj);
	if (src == NULL || da == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	env->SetByteArrayRegion(da, doffset, len, (src + soffset));

	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferTo
 * Signature: (Lorg/jnetpcap/JMemory;III)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferTo__Lorg_jnetpcap_nio_JMemory_2III(
		JNIEnv *env, jobject obj, jobject jdst, jint jsrcOffset, jint jlen,
		jint jdstOffset) {
	
	char *src = (char *) getJMemoryPhysical(env, obj);
	if (src == NULL || jdst == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	char *dst = (char *) getJMemoryPhysical(env, jdst);
	if (dst == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	size_t srcLen = env->GetIntField(obj, jmemorySizeFID);
	size_t dstLen = env->GetIntField(jdst, jmemorySizeFID);

	if (jsrcOffset < 0 || jdstOffset < 0 || jsrcOffset + jlen > srcLen
			|| jdstOffset + jlen > dstLen) {

		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "");
		return -1;
	}

	jlen = (dstLen < jlen) ? dstLen : jlen;

	memcpy((void *) (dst + jdstOffset), (void *) (src + jsrcOffset), jlen);

	return jlen;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferToDirect
 * Signature: (Ljava/nio/ByteBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferToDirect__Ljava_nio_ByteBuffer_2II(
		JNIEnv *env, jobject obj, jobject jbytebuffer, jint jsrcOffset,
		jint len) {

	char *src = (char *) getJMemoryPhysical(env, obj);
	if (src == NULL || jbytebuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	//	jint capacity = env->CallIntMethod(jbytebuffer, bufferGetCapacityMID);
	jint limit = env->CallIntMethod(jbytebuffer, bufferGetLimitMID);
	jint position = env->CallIntMethod(jbytebuffer, bufferGetPositionMID);
	jsize dstLen = limit - position;

	size_t srcLen = env->GetIntField(obj, jmemorySizeFID);
	if (jsrcOffset < 0 || (jsrcOffset + len) > srcLen) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);

		return -1;
	}

	if (dstLen < len) {
		throwVoidException(env, BUFFER_OVERFLOW_EXCEPTION);
		return -1;
	}

	char *b = (char *) env->GetDirectBufferAddress(jbytebuffer);

	memcpy(b + position, (void *) (src + jsrcOffset), len);
#ifdef DEBUG
	printf("JMemory.transferTo(ByteBuffer): position=%d limit=%d len=%d\n",
			position, limit, len);
#endif

	env->CallObjectMethod(jbytebuffer, bufferSetPositionMID, position + len);

	return len;
}

/****************************************************************
 * **************************************************************
 *
 * Java declared native functions for jReference class
 *
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_nio_JReference
 * Method:    cleanupReferences
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JReference_cleanupReferences
(JNIEnv *env, jobject obj) {

	jni_global_ref_t *refs = (jni_global_ref_t *)getJMemoryPhysical(env, obj);
	if (refs == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return;
	}

	for (int i = 0; i < refs->count; i ++) {
		if (refs->reference[i] != NULL) {
			env->DeleteGlobalRef(refs->reference[i]);
			refs->reference[i] = NULL;
		}
	}

	refs->count = 0;
}


/*
 * Class:     org_jnetpcap_nio_JReference
 * Method:    toDebugString
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_jnetpcap_nio_JReference_toDebugString(
		JNIEnv *env, jobject obj) {
	jni_global_ref_t *refs = (jni_global_ref_t *) getJMemoryPhysical(env, obj);
	if (refs == NULL) {
		return NULL;
	}

	char *c = str_buf;
	c += sprintf(c, "capacity=%d", refs->count);
	for (int i = 0; i < refs->count; i++) {
		c += sprintf(c, ", [%d]@%p", i, refs->reference[i]);
	}

	return env->NewStringUTF(str_buf); // Return local reference
}

/*
 * Class:     org_jnetpcap_nio_JReference
 * Method:    getCapacity
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JReference_getCapacity(
		JNIEnv *env, jobject obj) {
	jni_global_ref_t *refs = (jni_global_ref_t *) getJMemoryPhysical(env, obj);
	if (refs == NULL) {
		return -1;
	}

	return refs->count;
}



jobject jmemoryRefCreate(JNIEnv *env, jobject jmemory, jobject local_ref) {

	jobject jref = env->GetObjectField(jmemory, jmemoryReferencesFID);
	if (jref == NULL) {
		/* Create the native structure with default values */
#define REF_COUNT org_jnetpcap_nio_JReference_DEFAULT_REFERENCE_COUNT
#define REF_SIZE sizeof(jni_global_ref_t) + sizeof(jobject) * REF_COUNT
		jni_global_ref_t *refs = (jni_global_ref_t *) malloc(REF_SIZE);
		if (refs == NULL) {
			throwVoidException(env, OUT_OF_MEMORY_ERROR);
			return NULL; // Out of memory
		}
		refs->count = REF_COUNT;
		for (int i = 0; i < REF_COUNT; i++) {
			refs->reference[i] = NULL;
		}

		/* Create the JReference object and initialize it to our structure */
		jref = env->NewObject(jreferenceClass, jreferenceConstVoidMID);
		if (jref == NULL) {
			return NULL; // Out of memory
		}

		env->SetLongField(jref, jmemoryPhysicalFID, toLong(refs));
		env->SetIntField(jref, jmemorySizeFID, REF_SIZE);

		/* Set the JReference object in parent JMemory object */
		env->SetObjectField(jmemory, jmemoryReferencesFID, jref);
	}

	return jreferenceCreate(env, jref, local_ref);
}

jobject jreferenceCreate(JNIEnv *env, jobject obj, jobject local_ref) {

	jni_global_ref_t *refs = (jni_global_ref_t *) getJMemoryPhysical(env, obj);
	if (refs == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return NULL;
	}

	/*
	 * Lets see if we can reuse any previously cleared slots
	 */
	for (int i = 0; i < refs->count; i++) {
		if (refs->reference[i] == NULL) {
			jobject global_ref = env->NewGlobalRef(local_ref);
			if (global_ref == NULL) {
				return NULL; // Out of memory
			}

			refs->reference[i] = global_ref;

			return global_ref; // We're done
		}
	}

	/*
	 * We didn't find an empty slot so we have to resize and all some
	 */
	size_t old_size = sizeof(jni_global_ref_t) + refs->count * sizeof(jobject);
	size_t new_size = old_size + sizeof(jobject) * REF_COUNT;
	void *old_mem = refs;
	void *new_mem = malloc(new_size);
	if (new_mem == NULL) {
		throwVoidException(env, OUT_OF_MEMORY_ERROR);
		return NULL; // Out of memory
	}

	refs = (jni_global_ref_t *) memcpy(new_mem, old_mem, old_size);
	free(old_mem);

	env->SetLongField(obj, jmemoryPhysicalFID, toLong(refs));
	env->SetIntField(obj, jmemorySizeFID, new_size);

	for (int i = refs->count; i < refs->count + REF_COUNT; i++) {
		refs->reference[i] = NULL; // Initialize
	}

	refs->count += REF_COUNT;

	/*
	 * Lets try it again, this time with room to spare.
	 */
	return jreferenceCreate(env, obj, local_ref);
}

void jmemoryRefRelease(JNIEnv *env, jobject jmemory, jobject global_ref) {
	jobject jref = env->GetObjectField(jmemory, jmemoryReferencesFID);
	if (jref == NULL) {
		return; // Nothing to do
	}

	jreferenceRelease(env, jref, global_ref);
}

void jreferenceRelease(JNIEnv *env, jobject jref, jobject global_ref) {

	jni_global_ref_t *refs = (jni_global_ref_t *) getJMemoryPhysical(env, jref);
	if (refs == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JReference NULL ptr");
		return;
	}

	env->DeleteGlobalRef(global_ref);

	for (int i = 0; i < refs->count; i++) {
		if (refs->reference[i] == global_ref) {
			refs->reference[i] = NULL;
		}
	}

}

void *getJMemoryPhysical(JNIEnv *env, jobject obj) {

	jlong pt = env->GetLongField(obj, jmemoryPhysicalFID);
	return toPtr(pt);
}

jobject last = NULL;

void setJMemoryPhysical(JNIEnv *env, jobject obj, jlong value) {
	/*
	 * Make sure we clean up any previous allocations before we set new ptr
	 * and loose track of the old memory. In essence, this call in this function
	 * makes all JMemory.peer functions call JMemory.cleanup ;)
	 */
	jmemoryCleanup(env, obj);

	env->SetLongField(obj, jmemoryPhysicalFID, value);

//	printf("setJMemoryPhysical() obj=%p mem=%p\n", obj, toPtr(value));fflush(stdout);
//	char buf[1024];
//	printf("%s\n", jmemoryToDebugString(env, obj, buf));

	last = obj;
}

char *jmemoryToDebugString(JNIEnv *env, jobject obj, char *buf) {
	jstring jstr = (jstring) env->CallObjectMethod(obj, jmemoryToDebugStringMID);
	if (jstr == NULL) {
		return (char *)"ERROR in jmemoryToDebugString";
	}

	int len = env->GetStringUTFLength(jstr);
	const char *str = env->GetStringUTFChars(jstr, NULL);
	buf[len] = '\0';
	strncpy(buf, str, len);
	env->ReleaseStringUTFChars(jstr, str);

	return buf;
}

void jmemoryCleanup(JNIEnv *env, jobject obj) {

	void *mem = getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		return; // Nothing to do
	}

#ifdef DEBUG
	char buf[1024];
	printf("\n%p jmemoryCleanup() obj=%p\n", env, obj);fflush(stdout);
	printf("%s\n", jmemoryToDebugString(env, obj, buf));
#endif

	jboolean jowner = env->GetBooleanField(obj, jmemoryOwnerFID);
	if (mem != NULL && jowner) {
		/*
		 * Record statistics
		 */
		jint psize = env->GetIntField(obj, jmemoryPhysicalSizeFID);
		jint size = env->GetIntField(obj, jmemorySizeFID);
		memory_usage.total_deallocated += psize;
		memory_usage.total_deallocate_calls ++;

#ifdef DEBUG
		printf("%p jmemoryCleanup() free size=%d psize=%d mem=%p obj=%p jowner=%d\n", env, size, psize, mem, obj, jowner);
		fflush(stdout);
#endif
		/*
		 * Release the main structure
		 */
		free(mem);
		env->SetIntField(obj, jmemoryPhysicalSizeFID, (jint) 0);
	} else {
#ifdef DEBUG
		printf("%p jmemoryCleanup() %p not owner\n", env, obj);fflush(stdout);
#endif
	}

	env->SetLongField(obj, jmemoryPhysicalFID, (jlong) 0);
	env->SetBooleanField(obj, jmemoryOwnerFID, JNI_FALSE);
	env->SetIntField(obj, jmemorySizeFID, (jint)0);
	env->SetObjectField(obj, jmemoryKeeperFID, (jobject) NULL);
}

/**
 * Change the size of the peered object. The physicalSize remains unchanged.
 */
void jmemoryResize(JNIEnv *env, jobject obj, size_t size) {
	env->SetIntField(obj, jmemorySizeFID, (jsize) size);
}


/**
 * Provides a flexible peer method that can be called from JNI code
 */
jint jmemoryPeer(JNIEnv *env, jobject obj, const void *ptr, size_t length,
		jobject owner) {

#ifdef DEBUG
	char buf[1024];
	printf("%p jmemoryPeer() obj=%p\n", env, obj);fflush(stdout);
	printf("%s\n", jmemoryToDebugString(env, obj, buf));
#endif
	/*
	 * Make sure we release any previously held resources
	 */
	void *mem = getJMemoryPhysical(env, obj);
	if (mem != NULL && mem != ptr) {
#ifdef DEBUG
		printf("%p jmemoryPeer() doing cleanup mem=%p obj=%p owner=%p\n", env, mem, obj, owner); fflush(stdout);
#endif
		jmemoryCleanup(env, obj);
	}

	setJMemoryPhysical(env, obj, toLong((void *) ptr));
	env->SetIntField(obj, jmemorySizeFID, (jsize) length);
	env->SetObjectField(obj, jmemoryKeeperFID, owner);

	env->SetBooleanField(obj, jmemoryOwnerFID, (owner == obj) ? JNI_TRUE
			: JNI_FALSE);
	env->SetIntField(obj, jmemoryPhysicalSizeFID, (owner == obj) ? (jsize) length : 0);

#ifdef DEBUG
	printf("%p jmemoryPeer() obj=%p owner=%d\n", env, obj, (owner == obj)); fflush(stdout);
#endif

	return (jint) length;
}

/**
 * Allocates a memory block that is JMemory managed. The memory is allocated
 * under the control of the global memory pool (a java object).
 *
 * @param env
 * 	   java environment
 * @param size
 *     amount of memory to allocate in bytes
 * @param obj_ref
 *     a pointer to where store the JMemory object reference that owns the
 *     allocated memory block
 */
char *jmemoryPoolAllocate(JNIEnv *env, size_t size, jobject *obj_ref) {

	*obj_ref = env->CallObjectMethod(jmemoryPoolClass, jmemoryPoolAllocateExclusiveMID, (jint) size);

	return (char *) getJMemoryPhysical(env, *obj_ref);
}

/**
 * Allocates a single memory block for the java obj as its owner.
 *
 * @param env
 * 	   java environment
 * @param size
 *     amount of memory to allocate in bytes
 * @param obj
 *     obj under which to allocate the memory
 */
char *jmemoryAllocate(JNIEnv *env, size_t size, jobject obj) {

#ifdef DEBUG
	printf("\n%p jmemoryAllocate() ENTER\n", env); fflush(stdout);
#endif

#ifdef DEBUG
	printf("%p jmemoryAllocate() malloc size=%d\n", env, size); fflush(stdout);
#endif
	void *mem = malloc(size);
	if (mem == NULL) {
		printf("%p EXCEPTION mem==NULL\n", env); fflush(stdout);
		throwException(env, OUT_OF_MEMORY_ERROR, "");
		return NULL;
	}

#ifdef DEBUG
	printf("%p jmemoryAllocate() set to zero mem=%p size=%d\n", env, mem, size); fflush(stdout);
#endif

	/*
	 * Initialize allocated memory
	 */
	memset(mem, 0, size);

#ifdef DEBUG
	printf("%p jmemoryAllocate() setup\n", env); fflush(stdout);
#endif

	jmemoryPeer(env, obj, mem, size, obj);

#ifdef DEBUG
	char buf[1024];
	printf("%s\n", jmemoryToDebugString(env, obj, buf));
#endif

	jint jsize = (jint) size;

#ifdef DEBUG
	printf("%p jmemoryAllocate() usage\n", env); fflush(stdout);
#endif
	memory_usage.total_allocated += jsize;
	memory_usage.total_allocate_calls ++;

	if (jsize <= 255) {
		memory_usage.seg_0_255_bytes ++;
	} else {
		memory_usage.seg_256_or_above_bytes ++;
	}
#ifdef DEBUG
	printf("%p jmemoryAllocate() EXIT\n", env); fflush(stdout);
#endif
	return (char *)mem;
}

/**
 * Retrieves the size field of the JMemory object
 */
size_t getJMemorySize(JNIEnv *env, jobject obj) {
	return (size_t) env->GetIntField(obj, jmemorySizeFID);
}
