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
#include "export.h"

/*
 * JMemory.class
 */
jclass CLASS_jmemory = NULL;
jfieldID FID_jmemory_physical = 0;
jfieldID FID_jmemory_POINTER = 0;
jmethodID MID_jmemory_toDebugString = 0;
jmethodID MID_jmemory_toString = 0;
jobject JREF_jmemory_POINTER = NULL;

/*
 * ByteBuffer.class
 */
jclass CLASS_buffer = NULL;
jmethodID MID_buffer_isDirect = 0;
jmethodID MID_buffer_position = 0;
jmethodID MID_buffer_limit = 0;
jmethodID MID_buffer_set_position = 0;

/*
 * java.nio.Object.class - Object class methods
 */
jclass	CLASS_object = NULL;
jmethodID MID_object_toString = 0;

/*
 * java.lang.Class.class - Class file operations
 */
jclass CLASS_class = NULL;
jmethodID MID_class_getName = 0;
jmethodID MID_class_getSimpleName = 0;


/****************************************************************
 * **************************************************************
 *
 * Java declared native functions for jMemory class
 *
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_initIDs
(JNIEnv *env, jclass clazz) {
	
	jnp_add_messages(JNP_FAMILY_JMEM, jmem_message_table);

	memset(&GLOBAL_memory_usage, 0, sizeof(memory_usage_t));

	jnp_id_start(env, clazz);
	jnp_c(CLASS_jmemory,             "org/jnetpcap/nio/JMemory");
	jnp_f(FID_jmemory_physical,      "physical",      "J");
	jnp_m(MID_jmemory_toDebugString, "toDebugString", "()Ljava/lang/String;");
	jnp_m(MID_jmemory_toString,      "toString", "()Ljava/lang/String;");
	jnp_id_end();

	jnp_id_start(env, clazz);
	jnp_c(CLASS_buffer,            "java/nio/ByteBuffer");
	jnp_m(MID_buffer_position,     "position", "()I");
	jnp_m(MID_buffer_set_position, "position", "(I)Ljava/nio/Buffer;");
	jnp_m(MID_buffer_limit,        "limit",    "()I");
	jnp_m(MID_buffer_isDirect,     "isDirect", "()Z");
	jnp_id_end();
	
	jnp_id_start(env, clazz);
	jnp_c(CLASS_object,            "java/lang/Object");
	jnp_m(MID_object_toString,     "toString", "()Ljava/lang/String;");
	jnp_id_end();
	
	jnp_id_start(env, clazz);
	jnp_c(CLASS_class,            "java/lang/Class");
	jnp_m(MID_class_getName,   	  "getName", "()Ljava/lang/String;");
	jnp_m(MID_class_getSimpleName,"getSimpleName", "()Ljava/lang/String;");
	jnp_id_end();

}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocateCalls
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocateCalls(
		JNIEnv *env, jclass clazz) {
	return (jlong) memory_usage()->total_allocate_calls;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocated
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocated(
		JNIEnv *env, jclass clazz) {
	return (jlong) memory_usage()->total_allocated;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocatedSegments0To255Bytes
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocatedSegments0To255Bytes(
		JNIEnv *env, jclass clazz) {
	return (jlong) memory_usage()->seg_0_255_bytes;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalAllocatedSegments256OrAbove
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalAllocatedSegments256OrAbove(
		JNIEnv *env, jclass clazz) {
	return (jlong) memory_usage()->seg_256_or_above_bytes;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalDeAllocateCalls
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalDeAllocateCalls(
		JNIEnv *env, jclass clazz) {
	return (jlong) memory_usage()->total_deallocate_calls;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    totalDeAllocated
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JMemory_totalDeAllocated(
		JNIEnv *env, jclass clazz) {
	return (jlong) memory_usage()->total_deallocated;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    createBlockNode
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_createBlockNode
(JNIEnv *env, jobject obj, jint size) {

	jnp_enter("JMemory_createBlockNode");
	
	/*
	 * Not allowed to reconnect nodes. Nodes must be java discarded as there
	 * may be references hanging around to owner java objects.
	 */
	if (jmem_is_connected(env, obj) == JMEM_TRUE) {
		jnp_exit_exception_code(env, JMEM_ALREADY_CONNECTED);
		return;
	}

	block_t *node = jblock_create((size_t) size);
	if (node == NULL) {
		jnp_exit_error();
		return;
	}

	if (jmem_connect(env, obj, &node->h)) {
		jnp_exit_error();
		return;
	}

	jnp_exit_OK();
	return;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    createJRefNode
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_createJRefNode
(JNIEnv *env, jobject obj) {

	jnp_enter("JMemory_createJRefNode");
	
	/*
	 * Not allowed to reconnect nodes. Nodes must be java discarded as there
	 * may be references hanging around to owner java objects.
	 */
	if (jmem_is_connected(env, obj) == JMEM_TRUE) {
		jnp_exit_exception_code(env, JMEM_ALREADY_CONNECTED);
		return;
	}

	jref_t *node = jref_create();
	if (node == NULL) {
		jnp_exit_error();
		return;
	}

	if (jmem_connect(env, obj, &node->h)) {
		jnp_exit_error();
		return;
	}

	jnp_exit_OK();
	return;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    createPeerNode
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_createPeerNode
(JNIEnv *env, jobject obj) {

	jnp_enter("JMemory_createPeerNode");
	/*
	 * Not allowed to reconnect nodes. Nodes must be java discarded as there
	 * may be references hanging around to owner java objects.
	 */
	if (jmem_is_connected(env, obj) == JMEM_TRUE) {
		jnp_exit_exception_code(env, JMEM_ALREADY_CONNECTED);
		return;
	}

	peer_t *node = jpeer_create();
	if (node == NULL) {
		jnp_exit_error();
		return;
	}

	if (jmem_connect(env, obj, &node->h)) {
		jnp_exit_error();
		return;
	}

	jnp_exit_OK();
	return;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    free
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_free
(JNIEnv *env, jobject obj) {
	jnp_enter("JMemory_free");

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return;
	}

	if (jmem_free(env, node)) {
		jnp_exit_error();
		return;
	}
	
	jnp_exit_OK();
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    isActive
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_jnetpcap_nio_JMemory_isActive
(JNIEnv *env, jobject obj) {
	jnp_enter("JMemory_isActive");

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return JNI_FALSE;
	}

	jnp_exit_OK();
	return (jboolean) jmem_is_active(node);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    jmemoryFlags
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_jmemoryFlags__
(JNIEnv *env, jobject obj) {
	jnp_enter("JMemory_jmemoryFlags");

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return -1;
	}

	jnp_exit_OK();
	return (jint) node->flags;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    jmemoryFlags
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_jmemoryFlags__I
  (JNIEnv *env, jobject obj, jint flags) {
	jnp_enter("JMemory_jmemoryFlags__I");
	
	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return;
	}
	
	node->flags = flags;
	jnp_exit_OK();
}


/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    jmemoryNext
 * Signature: ()Lorg/jnetpcap/nio/JMemory;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_nio_JMemory_jmemoryNext
(JNIEnv *env, jobject obj) {

	throwException(env, UNSUPPORTED_OPERATION_EXCEPTION, "jmemoryNext");
	return NULL;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    jmemoryType
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_jmemoryType
(JNIEnv *env, jobject obj) {
	jnp_enter("JMemory_jmemoryType");

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return -1;
	}

	jnp_exit_OK();
	return (jint) node->type;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    jpeerJRef
 * Signature: ()Ljava/lang/Object;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_nio_JMemory_jpeerJRef
(JNIEnv *env, jobject obj) {
	jnp_enter("JMemory_jpeerJRef");

	peer_t *node = jpeer_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return NULL;
	}

	jnp_exit_OK();
	return node->jref;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    jrefJRef
 * Signature: ()Ljava/lang/Object;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_nio_JMemory_jrefJRef
(JNIEnv *env, jobject obj) {
	jnp_enter("JMemory_jrefJRef");

	jref_t *node = jref_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return NULL;
	}

	jnp_exit_OK();
	return node->jref;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    peer
 * Signature: (Ljava/nio/ByteBuffer;)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_peer__Ljava_nio_ByteBuffer_2
(JNIEnv *env, jobject obj, jobject buffer) {
	jnp_enter("JMemory_peer_ByteBuffer");

	if (buffer == NULL) {
		jnp_exit_exception_code(env, JNP_NULL_ARG);
		return -1;
	}

	peer_t *peer = jpeer_get(env, obj);
	if (peer == NULL || jmem_reset(env, &peer->h)) {
		jnp_exit_error();
		return -1;
	}

	jint position = env->CallIntMethod(buffer, MID_buffer_position);
	jint limit = env->CallIntMethod(buffer, MID_buffer_limit);

	char *b = (char *) env->GetDirectBufferAddress(buffer);
	if (b == NULL) {
		jnp_exit_exception_code(env, JMEM_ILLEGAL_PEER); // Not a direct buffer
		return -1;
	}

	if (jpeer_ref_direct(env,
					peer,
					b + position,
					(limit - position),
					buffer)) {
		jnp_exit_error();
		return -1;
	}

	jnp_exit_OK();
	return (limit - position);
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    peer
 * Signature: (Lorg/jnetpcap/nio/JMemory;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_peer__Lorg_jnetpcap_nio_JMemory_2II
(JNIEnv *env, jobject obj, jobject source, jint offset, jint length) {
	jnp_enter("JMemory_peer_JMemory");

	peer_t *us = jpeer_get(env, obj);
	if (us == NULL || jmem_reset(env, &us->h)) {
		jnp_exit_error();
		return -1;
	}

	jmemory_t *them = jmem_get(env, source);
	if (them == NULL || jmem_active(env, them)) {
		jnp_exit_error();
		return -1;
	}

	if (jpeer_ref_jmem_offset(env, us, offset, length, them)) {
		jnp_exit_error();
		return -1;
	}

	jnp_exit_OK();
	return length;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    reset
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JMemory_reset
(JNIEnv *env, jobject obj) {
	jnp_enter("JMemory_reset");

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return;
	}

	if (jmem_reset(env, node)) {
		jnp_exit_error();
		return; // Error
	}
	
	jnp_exit_OK();
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    size
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_size
(JNIEnv *env, jobject obj) {
	jnp_enter("JMemory_size");

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return -1;
	}

	size_t size = jmem_size(node);
	if (jnp_error()) {
		jnp_exit_exception(env);
		return -1; // Check for errors
	}

	jnp_exit_OK();
	return size;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferFrom
 * Signature: ([BIII)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferFrom
(JNIEnv *env, jobject obj, jbyteArray array, jint src_offset, jint len,
		jint dst_offset) {
	jnp_enter("JMemory_transferFrom_[B");

	if (array == NULL) {
		jnp_exit_exception_code(env, JNP_NULL_ARG);
		return -1;
	}

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return -1;
	}

	if (jmem_bounds(node, dst_offset, len)) {
		jnp_exception(env);
		jnp_exit_error();
		return -1;
	}

	jbyte *data = (jbyte *) jmem_data(node);
	if (data == NULL) {
		jnp_exit_error();
		return -1;
	}

	env->GetByteArrayRegion(array, src_offset, len, (data + dst_offset));

	jnp_exit_OK();
	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferFromDirect
 * Signature: (Ljava/nio/ByteBuffer;I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferFromDirect
(JNIEnv *env, jobject obj, jobject buffer, jint offset) {
	jnp_enter("JMemory_transferFromDirect_ByteBuffer");

	if (buffer == NULL) {
		jnp_exit_exception_code(env, JNP_NULL_ARG);
		return -1;
	}

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return -1;
	}

	jint position = env->CallIntMethod(buffer, MID_buffer_position);
	jint limit = env->CallIntMethod(buffer, MID_buffer_limit);
	jsize len = limit - position;

	if (jmem_bounds(node, offset, len)) {
		jnp_exit_exception(env);
		return -1;
	}

	char *dst = jmem_data(node);
	if (dst == NULL) {
		jnp_exit_exception(env);
		return -1;
	}

#ifdef DEBUG
	printf("JMemory.transferFrom(ByteBuffer): position=%d limit=%d len=%d\n",
			position, limit, len);
	fflush(stdout);
#endif

	char *b = (char *) env->GetDirectBufferAddress(buffer);
	if (b == NULL) {
		jnp_exit_exception_code(env, JMEM_ILLEGAL_TRANSFER); // Not a direct buffer
		return -1;
	}

	memcpy((void *) (dst + offset), b + position, len);

	env->CallObjectMethod(buffer, MID_buffer_set_position, position + len);

	jnp_exit_OK();
	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferTo
 * Signature: ([BIII)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferTo___3BIII
(JNIEnv *env, jobject obj, jbyteArray array, jint src_offset, jint len,
		jint dst_offset) {
	jnp_enter("JMemory_transferTo_[B");
	
	if (array == NULL) {
		jnp_exit_exception_code(env, JNP_NULL_ARG);
		return -1;
	}

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL && jmem_active(env, node)) {
		jnp_exit_error();
		return -1;
	}

	jint size = env->GetArrayLength(array);

	if (jmem_bounds(node, src_offset, len) || dst_offset + len> size) {
		jnp_exit_exception_code(env, JMEM_OUT_OF_BOUNDS);
		return -1;
	}

	jbyte *src = (jbyte *) jmem_data(node);
	if (src == NULL) {
		jnp_exit_exception(env);
		return -1;
	}

	env->SetByteArrayRegion(array, dst_offset, len, (src + src_offset));

	jnp_exit_OK();
	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferTo
 * Signature: (Lorg/jnetpcap/nio/JMemory;III)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferTo__Lorg_jnetpcap_nio_JMemory_2III
	(JNIEnv *env, jobject obj, jobject dst_obj, jint src_offset, jint len,
		jint dst_offset) {
	jnp_enter("JMemory_transferTo_JMemory");

	jmemory_t *us = jmem_get(env, obj);
	if (us == NULL) {
		jnp_exit_error();
		return -1;
	}
	jmemory_t *them = jmem_get(env, dst_obj);
	if (them == NULL) {
		jnp_exit_error();
		return -1;
	}

	char *src = jmem_data(us);
	if (src == NULL) {
		jnp_exit_exception(env);
		return -1;
	}

	char *dst = jmem_data(them);
	if (dst == NULL) {
		jnp_exit_exception(env);
		return -1;
	}

	size_t srcLen = jmem_size(us);
	size_t dstLen = jmem_size(them);

	if (jmem_bounds(us, src_offset, len)
			|| jmem_bounds(them, dst_offset, len)) {
		jnp_exit_exception(env);
		return -1;
	}

	memcpy((dst + dst_offset), (src + src_offset), len);

	jnp_exit_OK();
	return len;
}

/*
 * Class:     org_jnetpcap_nio_JMemory
 * Method:    transferToDirect
 * Signature: (Ljava/nio/ByteBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JMemory_transferToDirect
	(JNIEnv *env, jobject obj, jobject buffer, jint src_offset, jint len) {
	jnp_enter("JMemory_transferToDirect_ByteBuffer");
	
	if (buffer == NULL) {
		jnp_exit_exception_code(env, JNP_NULL_ARG);
		return -1;
	}
	
	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return -1;
	}

	char *src = (char *) jmem_data(node);
	if (src == NULL || jmem_bounds(node, src_offset, len)) {
		jnp_exit_exception(env);
		return -1;
	}

	jint position = env->CallIntMethod(buffer, MID_buffer_position);
	jint limit    = env->CallIntMethod(buffer, MID_buffer_limit);
	if (len > (limit - position)) {
		jnp_exit_exception_code(env, JMEM_OUT_OF_BOUNDS);
		return -1;
	}

	char *b = (char *) env->GetDirectBufferAddress(buffer);
	if (b == NULL) {
		jnp_exit_exception_code(env, JMEM_ILLEGAL_TRANSFER);
		return -1;
	}

	memcpy(b + position, (src + src_offset), len);
#ifdef DEBUG
	printf("JMemory.transferTo(ByteBuffer): position=%d limit=%d len=%d\n",
			position, limit, len);
#endif

	env->CallObjectMethod(buffer, MID_buffer_set_position, position + len);

	jnp_exit_OK();
	return len;
}
