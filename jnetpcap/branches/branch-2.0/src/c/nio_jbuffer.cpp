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

#include "nio_jbuffer.h"
#include "nio_jmemory.h"
#include "jnetpcap_utils.h"
#include "org_jnetpcap_nio_JBuffer.h"
#include "org_jnetpcap_nio_JObjectBuffer.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions. Private scan function
 * 
 * **************************************************************
 ****************************************************************/

#define jbuffer_is_big_endian(node) ((node->flags & JMEMORY_BIG_ENDIAN) != 0)

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/
jclass CLASS_jbuffer = NULL;

#define ITOA_BUF 16

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    initIds
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_initIds
(JNIEnv *env, jclass clazz) {

	CLASS_jbuffer = (jclass) env->NewGlobalRef(clazz);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getByte
 * Signature: (I)B
 */
JNIEXPORT jbyte JNICALL Java_org_jnetpcap_nio_JBuffer_getByte
(JNIEnv *env, jobject obj, jint index) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	if (jmem_bounds(node, index, 1)) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return 0;
	}

	return data[index];
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getByteArray
 * Signature: (I[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_nio_JBuffer_getByteArray__I_3B
(JNIEnv *env, jobject obj, jint index, jbyteArray array) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	size_t size = env->GetArrayLength(array);

	if (jmem_bounds(node, index, size)) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node);
	if (data == NULL) {
		jnp_exception(env);
		return NULL;
	}

	env->SetByteArrayRegion(array, 0, size, data + index);

	return array;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getByteArray
 * Signature: (I[BII)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_nio_JBuffer_getByteArray__I_3BII
(JNIEnv *env, jobject obj, jint index, jbyteArray array, jint offset, jint size) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return NULL;
	}

	if (jmem_bounds(node, index, size)) {
		jnp_exception(env);
		return NULL;
	}

	jint array_size = env->GetArrayLength(array);
	if (offset + size> array_size) {
		jnp_exception_code(env, JMEM_OUT_OF_BOUNDS);
		return NULL;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node);
	if (data == NULL) {
		jnp_exception(env);
		return NULL;
	}

	env->SetByteArrayRegion(array, offset, size, data + index);

	return array;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getByteArray
 * Signature: (II)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_nio_JBuffer_getByteArray__II
(JNIEnv *env, jobject obj, jint index, jint size) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	if (jmem_bounds(node, index, size)) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node);
	if (data == NULL) {
		jnp_exception(env);
		return NULL;
	}

	jbyteArray array = env->NewByteArray(size);
	if (array == NULL) {
		jnp_exception_code(env, JNP_OUT_OF_MEMORY);
	}

	env->SetByteArrayRegion(array, 0, size, data + index);

	return array;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getDouble
 * Signature: (I)D
 */
JNIEXPORT jdouble JNICALL Java_org_jnetpcap_nio_JBuffer_getDouble
(JNIEnv *env, jobject obj, jint index) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	if (jmem_bounds(node, index, sizeof(jdouble))) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return 0;
	}
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	u_int64_t long_data = *(u_int64_t *)(data + index);

	/*
	 * We can't just typecast u_int64 to a double. The double has to be read
	 * out of memory using a double pointer.
	 */
	long_data = ENDIAN64_GET(big, long_data);
	return *((jdouble *)&long_data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getFloat
 * Signature: (I)F
 */
JNIEXPORT jfloat JNICALL Java_org_jnetpcap_nio_JBuffer_getFloat
(JNIEnv *env, jobject obj, jint index) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	if (jmem_bounds(node, index, sizeof(jfloat))) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return 0;
	}
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	u_int32_t long_data = *(u_int32_t *)(data + index);

	/*
	 * We can't just typecast u_int64 to a double. The double has to be read
	 * out of memory using a double pointer.
	 */
	long_data = ENDIAN32_GET(big, long_data);
	return *((jfloat *)&long_data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getInt
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JBuffer_getInt
(JNIEnv *env, jobject obj, jint index) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	if (jmem_bounds(node, index, sizeof(jint))) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return 0;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register jint long_data = *(jint *)(data + index);

	return ENDIAN32_GET(big, long_data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getLong
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JBuffer_getLong
(JNIEnv *env, jobject obj, jint index) {
	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	if (jmem_bounds(node, index, sizeof(jlong))) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return 0;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int64_t long_data = *(u_int64_t *)(data + index);

	return ENDIAN64_GET(big, long_data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getShort
 * Signature: (I)S
 */
JNIEXPORT jshort JNICALL Java_org_jnetpcap_nio_JBuffer_getShort
(JNIEnv *env, jobject obj, jint index) {
	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	if (jmem_bounds(node, index, sizeof(jshort))) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return 0;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register jshort long_data = *(jshort *)(data + index);

	return ENDIAN16_GET(big, long_data);

}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getUByte
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JBuffer_getUByte
(JNIEnv *env, jobject obj, jint index) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	if (jmem_bounds(node, index, sizeof(jshort))) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return 0;
	}

	return (jint) ((u_int8_t)*(data + index));
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getUInt
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JBuffer_getUInt
(JNIEnv *env, jobject obj, jint index) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	if (jmem_bounds(node, index, sizeof(jint))) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return 0;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int32_t long_data = *(u_int32_t *)(data + index);

	return (jlong) ENDIAN32_GET(big, long_data);

}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getUShort
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JBuffer_getUShort
(JNIEnv *env, jobject obj, jint index) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return 0;
	}

	if (jmem_bounds(node, index, sizeof(jshort))) {
		jnp_exception(env);
		return 0;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return 0;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int16_t long_data = *(u_int16_t *)(data + index);

	return (jint) ENDIAN16_GET(big, long_data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setByte
 * Signature: (IB)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setByte
(JNIEnv *env, jobject obj, jint index, jbyte value) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	if (jmem_bounds(node, index, sizeof(value))) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_wo(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	*(data + index) = value;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setByteArray
 * Signature: (I[B)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setByteArray
(JNIEnv *env, jobject obj, jint index, jbyteArray array) {

	if (array == NULL) {
		jnp_exception_code(env, JNP_NULL_ARG);
		return;
	}

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	size_t size = env->GetArrayLength(array);

	if (jmem_bounds(node, index, size)) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_wo(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	env->GetByteArrayRegion(array, 0, size, (data + index));
	return;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setDouble
 * Signature: (ID)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setDouble
(JNIEnv *env, jobject obj, jint index, jdouble value) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	if (jmem_bounds(node, index, sizeof(value))) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_wo(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	u_int64_t long_data = *(u_int64_t *)(&value);

	/*
	 * We can't just typecast u_int32 to a float. The float has to be read
	 * out of memory using a float pointer.
	 */
	*((u_int64_t *)(data + index)) = ENDIAN64_GET(big, long_data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setFloat
 * Signature: (IF)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setFloat
(JNIEnv *env, jobject obj, jint index, jfloat value) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	if (jmem_bounds(node, index, sizeof(value))) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_wo(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	u_int32_t long_data = *(u_int32_t *)(&value);

	/*
	 * We can't just typecast u_int32 to a float. The float has to be read
	 * out of memory using a float pointer.
	 */
	*((u_int32_t *)(data + index)) = ENDIAN32_GET(big, long_data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setInt
 * Signature: (II)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setInt
(JNIEnv *env, jobject obj, jint index, jint value) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	if (jmem_bounds(node, index, sizeof(value))) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_wo(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	*((u_int32_t *)(data + index)) = ENDIAN32_GET(big, value);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setLong
 * Signature: (IJ)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setLong
(JNIEnv *env, jobject obj, jint index, jlong value) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	if (jmem_bounds(node, index, sizeof(value))) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_wo(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	*((u_int64_t *)(data + index)) = ENDIAN64_GET(big, value);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setShort
 * Signature: (IS)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setShort
(JNIEnv *env, jobject obj, jint index, jshort value) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	if (jmem_bounds(node, index, sizeof(value))) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_wo(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	*((u_int16_t *)(data + index)) = ENDIAN16_GET(big, value);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setUByte
 * Signature: (II)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setUByte
(JNIEnv *env, jobject obj, jint index, jint value) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	if (jmem_bounds(node, index, sizeof(jbyte))) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_wo(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	*(data + index) = (jbyte) value;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setUInt
 * Signature: (IJ)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setUInt
(JNIEnv *env, jobject obj, jint index, jlong value) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	if (jmem_bounds(node, index, sizeof(jint))) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_wo(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	register jint temp = (jint) value;

	*((u_int32_t *)(data + index)) = ENDIAN32_GET(big, temp);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setUShort
 * Signature: (II)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setUShort
(JNIEnv *env, jobject obj, jint index, jint value) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	if (jmem_bounds(node, index, sizeof(jshort))) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_wo(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = jbuffer_is_big_endian(node);

	register jshort temp = (jshort) value;

	*((u_int16_t *)(data + index)) = ENDIAN16_GET(big, temp);
}

/*
 * Class:     org_jnetpcap_nio_JObjectBuffer
 * Method:    getObject
 * Signature: (Ljava/lang/Class;I)Ljava/lang/Object;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_nio_JObjectBuffer_getObject
(JNIEnv *env, jobject obj, jclass clazz, jint index) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return NULL;
	}

	if (jmem_bounds(node, index, sizeof(jref_t *))) {
		jnp_exception(env);
		return NULL;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return NULL;
	}

	jref_t *jref = (jref_t *)(data + index);
	return (jref == NULL) ? NULL : jref->jref;
}

/*
 * Class:     org_jnetpcap_nio_JObjectBuffer
 * Method:    setObject
 * Signature: (ILjava/lang/Object;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JObjectBuffer_setObject
(JNIEnv *env, jobject obj, jint index, jobject object) {

	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		return;
	}

	if (jmem_bounds(node, index, sizeof(jref_t *))) {
		jnp_exception(env);
		return;
	}

	jbyte *data = (jbyte *)jmem_data_ro(node); // For reading
	if (data == NULL) {
		jnp_exception(env);
		return;
	}

	jref_t *jref = jref_create();
	if (jref == NULL) {
		jnp_exception(env);
		return;
	}
	
	// TODO: jmem_seg_attach(node, jref);

	if (jref_ref(env, jref, object) ) {
		return;
	}
	
	jref_t **p = (jref_t **)(data + index);

	*p = jref;
}

/*
 * Class:     org_jnetpcap_nio_JObjectBuffer
 * Method:    sizeofJObject
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JObjectBuffer_sizeofJObject
(JNIEnv *env, jclass clazz) {

	return sizeof(jobject);
}

