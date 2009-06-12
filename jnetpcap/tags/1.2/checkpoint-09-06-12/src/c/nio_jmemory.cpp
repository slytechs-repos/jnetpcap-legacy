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

void *getJMemoryPhysical(JNIEnv *env, jobject obj) {

	jlong pt = env->GetLongField(obj, jmemoryPhysicalFID);
	return toPtr(pt);
}

void setJMemoryPhysical(JNIEnv *env, jobject obj, jlong value) {
	/*
	 * Make sure we clean up any previous allocations before we set new ptr
	 * and loose track of the old memory. In essence, this call in this function
	 * makes all JMemory.peer functions call JMemory.cleanup ;)
	 */
	jmemoryCleanup(env, obj);
	
	env->SetLongField(obj, jmemoryPhysicalFID, value);
}

void jmemoryCleanup(JNIEnv *env, jobject obj) {
	Java_org_jnetpcap_nio_JMemory_cleanup(env, obj);	
}

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions for jMemory class
 * 
 * **************************************************************
 ****************************************************************/

jclass jmemoryClass = 0;
jclass jreferenceClass = 0;

jmethodID jreferenceConstVoidMID = 0;

jfieldID jmemoryPhysicalFID = 0;
jfieldID jmemoryPhysicalSizeFID = 0;
jfieldID jmemorySizeFID = 0;
jfieldID jmemoryOwnerFID = 0;
jfieldID jmemoryKeeperFID = 0;
jfieldID jmemoryReferencesFID = 0;

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



	
#ifdef DEBUG
	printf("initIds() - SUCCESS");
#endif

}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocateCalls
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocateCalls
  (JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_allocate_calls;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocated
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocated
(JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_allocated;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocatedSegments0To255Bytes
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocatedSegments0To255Bytes
(JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.seg_0_255_bytes;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocatedSegments256OrAbove
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocatedSegments256OrAbove
(JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.seg_256_or_above_bytes;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalDeAllocateCalls
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalDeAllocateCalls
(JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_deallocate_calls;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalDeAllocated
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalDeAllocated
(JNIEnv *obj, jclass clazz) {
	return (jlong) memory_usage.total_deallocated;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    allocate
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_allocate
(JNIEnv *env, jobject obj, jint jsize) {

	void * mem = malloc((int) jsize);
	if (mem == NULL) {
		throwException(env, OUT_OF_MEMORY_ERROR, "");
		return;
	}

	/*
	 * Initialize allocated memory
	 */
	memset(mem, 0, (int) jsize);

	setJMemoryPhysical(env, obj, toLong(mem));
	env->SetBooleanField(obj, jmemoryOwnerFID, JNI_TRUE);
	env->SetIntField(obj, jmemorySizeFID, jsize);
	env->SetIntField(obj, jmemoryPhysicalSizeFID, jsize);
	
	memory_usage.total_allocated += jsize;
	memory_usage.total_allocate_calls ++;
		
	if (jsize <= 255) {
		memory_usage.seg_0_255_bytes ++;
	} else {
		memory_usage.seg_256_or_above_bytes ++;
	}
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    cleanup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_cleanup
(JNIEnv *env, jobject obj) {

	jboolean jowner = env->GetBooleanField(obj, jmemoryOwnerFID);
	void *mem = getJMemoryPhysical(env, obj);
	if (mem != NULL && jowner) {
		/*
		 * Record statistics
		 */
		memory_usage.total_deallocated += 
			env->GetIntField(obj, jmemoryPhysicalSizeFID);
		memory_usage.total_deallocate_calls ++;
		
		/*
		 * Release the main structure
		 */
		free(mem);
		env->SetIntField(obj, jmemoryPhysicalSizeFID, (jint) 0);
	}

	env->SetLongField(obj, jmemoryPhysicalFID, (jlong) 0);
	env->SetBooleanField(obj, jmemoryOwnerFID, JNI_FALSE);
	env->SetIntField(obj, jmemorySizeFID, (jint)0);
	env->SetObjectField(obj, jmemoryKeeperFID, (jobject) NULL);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    nativePeer
 * Signature: (Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_peer
(JNIEnv *env, jobject obj, jobject jbytebuffer) {

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

	char *b = (char *)env->GetDirectBufferAddress(jbytebuffer);
	setJMemoryPhysical(env, obj, toLong(b + position));

	env->SetIntField(obj, jmemorySizeFID, (jint) (limit - position));
	env->SetObjectField(obj, jmemoryKeeperFID, jbytebuffer);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferFrom
 * Signature: ([BIII)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferFrom___3BIII
  (JNIEnv *env, jobject obj, jbyteArray sa, jint soffset, jint len, jint doffset) {
	
	jbyte *src = (jbyte *)getJMemoryPhysical(env, obj);
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
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferFromDirect
  (JNIEnv *env, jobject obj, jobject jbytebuffer, jint offset) {
	
	char *dst = (char *)getJMemoryPhysical(env, obj);
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


	char *b = (char *)env->GetDirectBufferAddress(jbytebuffer);
	
	memcpy((void *)(dst + offset), b + position, len);
	
	env->CallObjectMethod(jbytebuffer, bufferSetPositionMID, position + len);
	
	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferTo
 * Signature: ([BIII)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferTo___3BIII
  (JNIEnv *env, jobject obj, jbyteArray da, jint soffset, jint len, jint doffset) {
	
	jbyte *src = (jbyte *)getJMemoryPhysical(env, obj);
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
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferTo__Lorg_jnetpcap_nio_JMemory_2III
(JNIEnv *env, jobject obj, jobject jdst, jint jsrcOffset, jint jlen, jint jdstOffset) {

	char *src = (char *)getJMemoryPhysical(env, obj);
	if (src == NULL || jdst == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	char *dst = (char *)getJMemoryPhysical(env, jdst);
	if (dst == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}

	size_t srcLen = env->GetIntField(obj, jmemorySizeFID);
	size_t dstLen = env->GetIntField(jdst, jmemorySizeFID);

	if (jsrcOffset < 0 
			|| jdstOffset < 0 
			|| jsrcOffset + jlen > srcLen 
			|| jdstOffset + jlen > dstLen) {

		throwException(env, INDEX_OUT_OF_BOUNDS_EXCEPTION, "");
		return -1;
	}
	
	jlen = (dstLen < jlen)?dstLen:jlen;

	memcpy((void *)(dst + jdstOffset), (void *)(src + jsrcOffset), jlen);
	
	return jlen;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferToDirect
 * Signature: (Ljava/nio/ByteBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferToDirect__Ljava_nio_ByteBuffer_2II
(JNIEnv *env, jobject obj, jobject jbytebuffer, jint jsrcOffset, jint len) {

	char *src = (char *)getJMemoryPhysical(env, obj);
	if (src == NULL || jbytebuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return -1;
	}
	
//	jint capacity = env->CallIntMethod(jbytebuffer, bufferGetCapacityMID);
	jint limit = env->CallIntMethod(jbytebuffer, bufferGetLimitMID);
	jint position = env->CallIntMethod(jbytebuffer, bufferGetPositionMID);
	jsize dstLen = limit - position;
	
	size_t srcLen = env->GetIntField(obj, jmemorySizeFID);
	if (jsrcOffset < 0 || len > srcLen) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		
		return -1;
	}
	
	if (dstLen < len) {
		throwVoidException(env, BUFFER_OVERFLOW_EXCEPTION);
		return -1;
	}


	char *b = (char *)env->GetDirectBufferAddress(jbytebuffer);
	
	memcpy(b + position, (void *)(src + jsrcOffset), len);
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
		for (int i = 0; i < REF_COUNT; i ++) {
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
	
	jni_global_ref_t *refs = (jni_global_ref_t *)getJMemoryPhysical(env, obj);
	if (refs == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "");
		return NULL;
	}
		
	/*
	 * Lets see if we can reuse any previously cleared slots 
	 */
	for (int i = 0; i < refs->count; i ++) {
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
	
	jni_global_ref_t *refs = (jni_global_ref_t *)getJMemoryPhysical(env, jref);
	if (refs == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JReference NULL ptr");
		return;
	}
	
	env->DeleteGlobalRef(global_ref);
	
	for (int i = 0; i < refs->count; i ++) {
		if (refs->reference[i] == global_ref) {
			refs->reference[i] = NULL;
		}
	}
	
}

/*
 * Class:     org_jnetpcap_nio_JReference
 * Method:    toDebugString
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_jnetpcap_nio_JReference_toDebugString
  (JNIEnv *env, jobject obj) {
	jni_global_ref_t *refs = (jni_global_ref_t *)getJMemoryPhysical(env, obj);
	if (refs == NULL) {
		return NULL;
	}

	char *c = str_buf;
	c += sprintf(c, "capacity=%d", refs->count);
	for (int i = 0; i < refs->count; i ++) {
		c += sprintf(c, ", [%d]@%x", i, refs->reference[i]);
	}
	
	return env->NewStringUTF(str_buf); // Return local reference
}

/*
 * Class:     org_jnetpcap_nio_JReference
 * Method:    getCapacity
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JReference_getCapacity
  (JNIEnv *env, jobject obj) {
	jni_global_ref_t *refs = (jni_global_ref_t *)getJMemoryPhysical(env, obj);
	if (refs == NULL) {
		return -1;
	}

	return refs->count;
}


