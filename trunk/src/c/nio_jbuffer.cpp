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


/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/
jfieldID jbufferOrderFID = 0;
jfieldID jbufferReadonlyFID = 0;

#define ITOA_BUF 16

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    initIds
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_initIds
(JNIEnv *env, jclass clazz) {

	jclass c = clazz;
	
	if ( ( jbufferOrderFID = env->GetFieldID(c, "order", "Z")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JBuffer.order:boolean");
		return;
	}

	if ( ( jbufferReadonlyFID = env->GetFieldID(c, "readonly", "Z")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JBuffer.readonly:boolean");
		return;
	}
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getByte
 * Signature: (I)B
 */
JNIEXPORT jbyte JNICALL Java_org_jnetpcap_nio_JBuffer_getByte
  (JNIEnv *env, jobject obj, jint jindex) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return -1;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex >= size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return -1;
	}
	
	return mem[jindex];
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getByteArray
 * Signature: (I[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_nio_JBuffer_getByteArray__I_3B
  (JNIEnv *env, jobject obj, jint jindex, jbyteArray jarray) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return NULL;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex >= size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return NULL;
	}
	
	size_t jarraySize = env->GetArrayLength(jarray);
	
	if (jindex + jarraySize > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		
		return NULL;
	}
	
	env->SetByteArrayRegion(jarray, 0, jarraySize, mem + jindex);
	
	return jarray;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getByteArray
 * Signature: (II)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_nio_JBuffer_getByteArray__II
  (JNIEnv *env, jobject obj, jint jindex, jint jarraySize) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		
		return NULL;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex >= size) {		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		
		return NULL;
	}
		
	if (jindex + jarraySize > size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		
		return NULL;
	}
	
	jbyteArray jarray = env->NewByteArray(jarraySize);
	
	env->SetByteArrayRegion(jarray, 0, jarraySize, (mem + jindex));
	
	return jarray;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getByteArray
 * Signature: (I[BII)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_nio_JBuffer_getByteArray__I_3BII
  (JNIEnv *env, jobject obj, jint jindex, jbyteArray jarray, jint offset, jint length) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return NULL;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex >= size || offset < 0 || length < 0) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return NULL;
	}
	
	size_t jarraySize = env->GetArrayLength(jarray);
	
	if (jindex + offset + length > size || offset + length > jarraySize) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		
		return NULL;
	}
	
	env->SetByteArrayRegion(jarray, offset, length, mem + jindex);
	
	return jarray;
}


/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getDouble
 * Signature: (I)D
 */
JNIEXPORT jdouble JNICALL Java_org_jnetpcap_nio_JBuffer_getDouble
  (JNIEnv *env, jobject obj, jint jindex) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return 0;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jdouble) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	 u_int64_t data = *(u_int64_t *)(mem + jindex);
	 
	/*
	 * We can't just typecast u_int64 to a double. The double has to be read
	 * out of memory using a double pointer.
	 */
	data = ENDIAN64_GET(big, data);
	return *((jdouble *)&data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getFloat
 * Signature: (I)F
 */
JNIEXPORT jfloat JNICALL Java_org_jnetpcap_nio_JBuffer_getFloat
  (JNIEnv *env, jobject obj, jint jindex) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return 0;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jfloat) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);
	
	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	u_int32_t data = *(u_int32_t *)(mem + jindex);

	/*
	 * We can't just typecast u_int32 to a float. The float has to be read
	 * out of memory using a float pointer.
	 */
	data = ENDIAN32_GET(big, data);
	return *((jfloat *)&data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getInt
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JBuffer_getInt
  (JNIEnv *env, jobject obj, jint jindex) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return 0;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jint) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register jint data = *(jint *)(mem + jindex);
	
	return ENDIAN32_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getLong
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JBuffer_getLong
  (JNIEnv *env, jobject obj, jint jindex) {
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return 0;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jlong) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int64_t data = *(u_int64_t *)(mem + jindex);
	
	return ENDIAN64_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getShort
 * Signature: (I)S
 */
JNIEXPORT jshort JNICALL Java_org_jnetpcap_nio_JBuffer_getShort
  (JNIEnv *env, jobject obj, jint jindex) {
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return 0;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jshort) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register jshort data = *(jshort *)(mem + jindex);
	
	return ENDIAN16_GET(big, data);

}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getUByte
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JBuffer_getUByte
  (JNIEnv *env, jobject obj, jint jindex) {
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return 0;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jbyte) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int8_t data = (u_int8_t)*(mem + jindex);
	
	return (jint) data;

}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getUInt
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JBuffer_getUInt
  (JNIEnv *env, jobject obj, jint jindex) {
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return 0;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jint) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int32_t data = *(u_int32_t *)(mem + jindex);
	
	return (jlong) ENDIAN32_GET(big, data);

}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getUShort
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JBuffer_getUShort
  (JNIEnv *env, jobject obj, jint jindex) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return 0;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jshort) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return 0;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int16_t data = *(u_int16_t *)(mem + jindex);
	
	return (jint) ENDIAN16_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setByte
 * Signature: (IB)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setByte
  (JNIEnv *env, jobject obj, jint jindex, jbyte jval) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jbyte) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return;
	}
	
	*(mem + jindex) = jval;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setByteArray
 * Signature: (I[B)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setByteArray
  (JNIEnv *env, jobject obj, jint jindex, jbyteArray jarray) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex >= size) {
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return;
	}
	
	size_t jarraySize = env->GetArrayLength(jarray);
	
	if (jindex + jarraySize > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		
		return;
	}
	
	env->GetByteArrayRegion(jarray, 0, jarraySize, (mem + jindex));
	
	return;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setDouble
 * Signature: (ID)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setDouble
  (JNIEnv *env, jobject obj, jint jindex, jdouble jval) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return;
	}
	
	jboolean readonly =  env->GetBooleanField(obj, jbufferReadonlyFID);
	if (readonly == JNI_TRUE) {
		
		throwVoidException(env, READ_ONLY_BUFFER_EXCETPION);
		return;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jdouble) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);
	
	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	u_int64_t data = *(u_int64_t *)(&jval);

	/*
	 * We can't just typecast u_int32 to a float. The float has to be read
	 * out of memory using a float pointer.
	 */
	*((u_int64_t *)(mem + jindex)) = ENDIAN64_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setFloat
 * Signature: (IF)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setFloat
  (JNIEnv *env, jobject obj, jint jindex, jfloat jval) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return;
	}
	
	jboolean readonly =  env->GetBooleanField(obj, jbufferReadonlyFID);
	if (readonly == JNI_TRUE) {
		
		throwVoidException(env, READ_ONLY_BUFFER_EXCETPION);
		return;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jfloat) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);
	
	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	u_int32_t data = *(u_int32_t *)(&jval);

	/*
	 * We can't just typecast u_int32 to a float. The float has to be read
	 * out of memory using a float pointer.
	 */
	*((u_int32_t *)(mem + jindex)) = ENDIAN32_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setInt
 * Signature: (II)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setInt
  (JNIEnv *env, jobject obj, jint jindex, jint jval) {
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return;
	}
	
	jboolean readonly =  env->GetBooleanField(obj, jbufferReadonlyFID);
	if (readonly == JNI_TRUE) {
		
		throwVoidException(env, READ_ONLY_BUFFER_EXCETPION);
		return;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jint) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);
	
	*((u_int32_t *)(mem + jindex)) = ENDIAN32_GET(big, jval);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setLong
 * Signature: (IJ)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setLong
  (JNIEnv *env, jobject obj, jint jindex, jlong jval) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return;
	}
	
	jboolean readonly =  env->GetBooleanField(obj, jbufferReadonlyFID);
	if (readonly == JNI_TRUE) {
		
		throwVoidException(env, READ_ONLY_BUFFER_EXCETPION);
		return;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jlong) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);
	
	*((u_int64_t *)(mem + jindex)) = ENDIAN64_GET(big, jval);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setShort
 * Signature: (IS)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setShort
  (JNIEnv *env, jobject obj, jint jindex, jshort jval) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return;
	}
	
	jboolean readonly =  env->GetBooleanField(obj, jbufferReadonlyFID);
	if (readonly == JNI_TRUE) {
		
		throwVoidException(env, READ_ONLY_BUFFER_EXCETPION);
		return;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jshort) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);
	
	*((u_int16_t *)(mem + jindex)) = ENDIAN16_GET(big, jval);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setUByte
 * Signature: (II)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setUByte
  (JNIEnv *env, jobject obj, jint jindex, jint jval) {

	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return;
	}
	
	jboolean readonly =  env->GetBooleanField(obj, jbufferReadonlyFID);
	if (readonly == JNI_TRUE) {
		
		throwVoidException(env, READ_ONLY_BUFFER_EXCETPION);
		return;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(jbyte) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return;
	}
	
	*(mem + jindex) = (jbyte) jval;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setUInt
 * Signature: (IJ)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setUInt
  (JNIEnv *env, jobject obj, jint jindex, jlong jval) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return;
	}
	
	jboolean readonly =  env->GetBooleanField(obj, jbufferReadonlyFID);
	if (readonly == JNI_TRUE) {
		
		throwVoidException(env, READ_ONLY_BUFFER_EXCETPION);
		return;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(int) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);
	
	register jint temp = (jint) jval;
	
	*((u_int32_t *)(mem + jindex)) = ENDIAN32_GET(big, temp);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setUShort
 * Signature: (II)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setUShort
  (JNIEnv *env, jobject obj, jint jindex, jint jval) {
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return;
	}
	
	jboolean readonly =  env->GetBooleanField(obj, jbufferReadonlyFID);
	if (readonly == JNI_TRUE) {
		
		throwVoidException(env, READ_ONLY_BUFFER_EXCETPION);
		return;
	}

	size_t size =  (size_t) env->GetIntField(obj, jmemorySizeFID);
	if (jindex < 0 || jindex + sizeof(short) > size) {
		
		throwVoidException(env, BUFFER_UNDERFLOW_EXCEPTION);
		return;
	}
	
	// true = BID_ENDIAN, false = LITTLE_ENDIAN
	jboolean big = env->GetBooleanField(obj, jbufferOrderFID);
	
	register jshort temp = (jshort) jval;
	
	*((u_int16_t *)(mem + jindex)) = ENDIAN16_GET(big, temp);
}


/*
 * Class:     org_jnetpcap_nio_JObjectBuffer
 * Method:    getObject
 * Signature: (Ljava/lang/Class;I)Ljava/lang/Object;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_nio_JObjectBuffer_getObject
  (JNIEnv *env, jobject obj, jclass clazz, jint offset) {
	
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return NULL;
	}
//#define DEBUG
#ifdef DEBUG
	printf("getObject(): here mem=%p offset=%d *=%p\n", 
			mem, 
			offset, 
			*((jobject *) (mem + offset)));
	fflush(stdout);
#endif
	return *((jobject *) (mem + offset));
}

/*
 * Class:     org_jnetpcap_nio_JObjectBuffer
 * Method:    setObject
 * Signature: (ILjava/lang/Object;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JObjectBuffer_setObject
  (JNIEnv *env, jobject obj, jint offset, jobject object) {
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return;
	}
	
	if (object == NULL) {
		return; // Nothing todo
	}
	
	jobject global_ref = jmemoryRefCreate(env, obj, object);
	if (global_ref == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "Failed to create global_ref");
		return;
	}
	
	*((jobject *)(mem + offset)) = global_ref; 
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

