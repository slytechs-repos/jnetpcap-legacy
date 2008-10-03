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

#include "jnetpcap_jnumber.h"
#include "jnetpcap_peered.h"
#include "org_jnetpcap_JNumber.h"
#include "export.h"


/*****************************************************************************
 *  These are static and constant unless class file reloads
 */


/*
 * Class:     org_jnetpcap_JNumber
 * Method:    intValue
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_JNumber_intValue__
  (JNIEnv *env, jobject obj) {
	
	jint *p = (jint *)getPeeredPhysical(env, obj);
	
	return *p;	
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    intValue
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_JNumber_intValue__I
  (JNIEnv *env, jobject obj, jint jvalue) {
	
	jint *p = (jint *)getPeeredPhysical(env, obj);
	*p = jvalue;
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    byteValue
 * Signature: ()B
 */
JNIEXPORT jbyte JNICALL Java_org_jnetpcap_JNumber_byteValue__
  (JNIEnv *env, jobject obj) {
	
	jbyte *p = (jbyte *)getPeeredPhysical(env, obj);
	return *p;	
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    byteValue
 * Signature: (B)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_JNumber_byteValue__B
  (JNIEnv *env, jobject obj, jbyte jvalue) {
	jbyte *p = (jbyte *)getPeeredPhysical(env, obj);
	*p = jvalue;
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    shortValue
 * Signature: ()S
 */
JNIEXPORT jshort JNICALL Java_org_jnetpcap_JNumber_shortValue__
  (JNIEnv *env, jobject obj) {
	
	jshort *p = (jshort *)getPeeredPhysical(env, obj);
	return *p;	
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    shortValue
 * Signature: (S)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_JNumber_shortValue__S
  (JNIEnv *env, jobject obj, jshort jvalue) {
	
	jshort *p = (jshort *)getPeeredPhysical(env, obj);
	*p = jvalue;
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    longValue
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_JNumber_longValue__
  (JNIEnv *env, jobject obj) {
	
	jlong *p = (jlong *)getPeeredPhysical(env, obj);
	return *p;	
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    longValue
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_JNumber_longValue__J
  (JNIEnv *env, jobject obj, jlong jvalue) {
	
	jlong *p = (jlong *)getPeeredPhysical(env, obj);
	*p = jvalue;
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    floatValue
 * Signature: ()F
 */
JNIEXPORT jfloat JNICALL Java_org_jnetpcap_JNumber_floatValue__
  (JNIEnv *env, jobject obj) {
	
	jfloat *p = (jfloat *)getPeeredPhysical(env, obj);
	return *p;	
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    floatValue
 * Signature: (F)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_JNumber_floatValue__F
  (JNIEnv *env, jobject obj, jfloat jvalue) {
	
	jfloat *p = (jfloat *)getPeeredPhysical(env, obj);
	*p = jvalue;
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    doubleValue
 * Signature: ()D
 */
JNIEXPORT jdouble JNICALL Java_org_jnetpcap_JNumber_doubleValue__
  (JNIEnv *env, jobject obj) {
	
	jdouble *p = (jdouble *)getPeeredPhysical(env, obj);
	return *p;	
}

/*
 * Class:     org_jnetpcap_JNumber
 * Method:    doubleValue
 * Signature: (D)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_JNumber_doubleValue__D
  (JNIEnv *env, jobject obj, jdouble jvalue) {
	
	jdouble *p = (jdouble *)getPeeredPhysical(env, obj);
	*p = jvalue;
}

